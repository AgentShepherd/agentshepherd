package rules

import (
	"encoding/json"
	"strings"
)

// ExtractedInfo contains paths and operation from a tool call
type ExtractedInfo struct {
	Operation Operation
	Paths     []string
	Hosts     []string
	Command   string // Raw command string (for Bash tool)
	Content   string // Content being written (for Write/Edit tools)
	RawArgs   map[string]any
}

// Extractor extracts paths and operations from tool calls
type Extractor struct {
	commandDB map[string]CommandInfo
}

// CommandInfo describes how to extract info from a command
type CommandInfo struct {
	Operation    Operation
	PathArgIndex []int    // positional args that are paths
	PathFlags    []string // flags followed by paths (-o, --output)
}

// NewExtractor creates a new Extractor with the default command database
func NewExtractor() *Extractor {
	return &Extractor{
		commandDB: defaultCommandDB(),
	}
}

// defaultCommandDB returns the default command database
func defaultCommandDB() map[string]CommandInfo {
	return map[string]CommandInfo{
		// ===========================================
		// READ OPERATIONS
		// ===========================================
		"cat":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"head": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"tail": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"less": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"more": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"grep": {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"vim":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"vi":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"nano": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"view": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// Binary inspection tools
		"strings": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"xxd":     {Operation: OpRead, PathArgIndex: []int{0}},
		"od":      {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"hexdump": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"file":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"stat":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// Text processing (read)
		"awk":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}},
		"sed":  {Operation: OpRead, PathArgIndex: []int{1, 2, 3, 4, 5}}, // -i becomes write but still reads first
		"cut":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"sort": {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"uniq": {Operation: OpRead, PathArgIndex: []int{0, 1}},
		"wc":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"diff": {Operation: OpRead, PathArgIndex: []int{0, 1}},

		// Archive tools (read contents)
		"tar":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}, PathFlags: []string{"-f", "--file"}},
		"zip":    {Operation: OpRead, PathArgIndex: []int{0, 1, 2, 3}},
		"unzip":  {Operation: OpRead, PathArgIndex: []int{0}},
		"gzip":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"gunzip": {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"zcat":   {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"bzip2":  {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},
		"xz":     {Operation: OpRead, PathArgIndex: []int{0, 1, 2}},

		// ===========================================
		// WRITE OPERATIONS
		// ===========================================
		"tee":   {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"touch": {Operation: OpWrite, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// ===========================================
		// DELETE OPERATIONS
		// ===========================================
		"rm":     {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		"unlink": {Operation: OpDelete, PathArgIndex: []int{0}},
		"shred":  {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"rmdir":  {Operation: OpDelete, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},

		// ===========================================
		// COPY OPERATIONS
		// ===========================================
		"cp":    {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"scp":   {Operation: OpCopy, PathArgIndex: []int{0, 1}},
		"rsync": {Operation: OpCopy, PathArgIndex: []int{0, 1, 2, 3, 4, 5}},
		"dd":    {Operation: OpCopy, PathFlags: []string{"if=", "of="}},

		// ===========================================
		// MOVE OPERATIONS
		// ===========================================
		"mv": {Operation: OpMove, PathArgIndex: []int{0, 1}},

		// ===========================================
		// NETWORK OPERATIONS
		// ===========================================
		"curl":     {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-o", "--output"}},
		"wget":     {Operation: OpNetwork, PathArgIndex: []int{0}, PathFlags: []string{"-O", "--output-document"}},
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
		"python":  {Operation: OpExecute, PathArgIndex: []int{0}},
		"python3": {Operation: OpExecute, PathArgIndex: []int{0}},
		"node":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"ruby":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"perl":    {Operation: OpExecute, PathArgIndex: []int{0}},
		"php":     {Operation: OpExecute, PathArgIndex: []int{0}},

		// Indirect execution
		"xargs":  {Operation: OpExecute, PathArgIndex: []int{0, 1, 2}},
		"find":   {Operation: OpExecute, PathArgIndex: []int{0}, PathFlags: []string{"-exec", "-execdir"}},
		"eval":   {Operation: OpExecute, PathArgIndex: []int{0}},
		"source": {Operation: OpExecute, PathArgIndex: []int{0}},
		".":      {Operation: OpExecute, PathArgIndex: []int{0}}, // source alias

		// Scheduled task commands
		"crontab": {Operation: OpExecute, PathArgIndex: []int{}},
		"at":      {Operation: OpExecute, PathArgIndex: []int{}},

		// ===========================================
		// SYMLINK OPERATIONS (important for bypass detection)
		// ===========================================
		"ln":       {Operation: OpWrite, PathArgIndex: []int{0, 1}},
		"readlink": {Operation: OpRead, PathArgIndex: []int{0}},
	}
}

// skipFlagsDB contains flags that take non-path arguments (value follows the flag)
var skipFlagsDB = map[string]bool{
	// head/tail
	"-n": true, "--lines": true,
	// grep (note: -f in grep takes a file, but we already handle paths)
	"-e": true, "--regexp": true,
	"-m": true, "--max-count": true, "-A": true, "-B": true, "-C": true,
	// general option flags (not boolean flags like -f for force or follow)
	"-c": true, "--count": true,
}

// Extract extracts info from a tool call
func (e *Extractor) Extract(toolName string, args json.RawMessage) ExtractedInfo {
	info := ExtractedInfo{
		RawArgs: make(map[string]any),
	}

	// Store raw args as Content for universal content matching
	info.Content = string(args)

	// Parse the raw args
	if err := json.Unmarshal(args, &info.RawArgs); err != nil {
		return info
	}

	// Normalize tool name for comparison
	toolLower := strings.ToLower(toolName)

	switch toolLower {
	case "bash":
		e.extractBashCommand(&info)
	case "read", "read_file":
		e.extractReadTool(&info)
	case "write", "write_file":
		e.extractWriteTool(&info)
	case "edit":
		e.extractEditTool(&info)
	case "webfetch":
		e.extractWebFetchTool(&info)
	default:
		// Unknown tool (including MCP): only extract generic paths
		// Content-only rules will handle matching via raw JSON
		e.extractGenericPaths(&info)
	}

	return info
}

// extractBashCommand parses a bash command and extracts paths/operation
func (e *Extractor) extractBashCommand(info *ExtractedInfo) {
	cmdRaw, ok := info.RawArgs["command"]
	if !ok {
		return
	}

	cmd, ok := cmdRaw.(string)
	if !ok {
		return
	}

	// Store the raw command for advanced rule matching
	info.Command = cmd

	// Parse the command into tokens
	tokens := tokenizeCommand(cmd)
	if len(tokens) == 0 {
		return
	}

	// Find the actual command (skip env vars, sudo, etc.)
	cmdIndex := 0
	for i, token := range tokens {
		// Skip environment variable assignments (FOO=bar)
		if strings.Contains(token, "=") && !strings.HasPrefix(token, "-") {
			continue
		}
		// Skip sudo, env, time, etc.
		if token == "sudo" || token == "env" || token == "time" || token == "nice" {
			continue
		}
		cmdIndex = i
		break
	}

	if cmdIndex >= len(tokens) {
		return
	}

	// Get the base command name (strip path)
	cmdName := tokens[cmdIndex]
	if idx := strings.LastIndex(cmdName, "/"); idx != -1 {
		cmdName = cmdName[idx+1:]
	}

	// Look up command in database
	cmdInfo, found := e.commandDB[cmdName]
	if found {
		info.Operation = cmdInfo.Operation
		// Extract paths from positional arguments
		e.extractPathsFromTokens(info, tokens[cmdIndex+1:], cmdInfo)
	}

	// Check for redirections which indicate write operation
	if hasWriteRedirection(cmd) {
		if info.Operation == "" {
			info.Operation = OpWrite
		}
		// Extract redirect targets
		paths := extractRedirectTargets(cmd)
		info.Paths = append(info.Paths, paths...)
	}

	// Deduplicate paths
	info.Paths = deduplicatePaths(info.Paths)

	// For network commands, extract hosts
	if info.Operation == OpNetwork {
		info.Hosts = extractHosts(tokens)
	}
}

// extractPathsFromTokens extracts paths from command tokens
func (e *Extractor) extractPathsFromTokens(info *ExtractedInfo, tokens []string, cmdInfo CommandInfo) {
	positionalIdx := 0
	skipNext := false

	for i, token := range tokens {
		if skipNext {
			skipNext = false
			continue
		}

		// Check if this is a flag that takes a path argument
		isPathFlag := false
		for _, flag := range cmdInfo.PathFlags {
			if token == flag {
				isPathFlag = true
				break
			}
		}

		if isPathFlag && i+1 < len(tokens) {
			// Next token is a path
			info.Paths = append(info.Paths, tokens[i+1])
			skipNext = true
			continue
		}

		// Check if this is a flag that takes a non-path argument (skip next token)
		if skipFlagsDB[token] {
			skipNext = true
			continue
		}

		// Skip flags (but not paths starting with - like ./-file)
		if strings.HasPrefix(token, "-") && !looksLikePath(token) {
			continue
		}

		// This is a positional argument
		for _, idx := range cmdInfo.PathArgIndex {
			if positionalIdx == idx {
				info.Paths = append(info.Paths, token)
				break
			}
		}
		positionalIdx++
	}
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

// extractGenericPaths extracts paths from common field names
func (e *Extractor) extractGenericPaths(info *ExtractedInfo) {
	e.extractPathFields(info)
}

// extractWebFetchTool extracts info from WebFetch tool
func (e *Extractor) extractWebFetchTool(info *ExtractedInfo) {
	info.Operation = OpNetwork

	// Extract URL from args
	urlRaw, ok := info.RawArgs["url"]
	if !ok {
		return
	}

	urlStr, ok := urlRaw.(string)
	if !ok || urlStr == "" {
		return
	}

	// Extract host from URL
	host := extractHostFromURL(urlStr)
	if host != "" {
		info.Hosts = append(info.Hosts, host)
	}
}

// extractPathFields extracts paths from known field names
func (e *Extractor) extractPathFields(info *ExtractedInfo) {
	pathFields := []string{"path", "file_path", "filepath", "filename", "file", "source", "destination", "target"}

	for _, field := range pathFields {
		if val, ok := info.RawArgs[field]; ok {
			if s, ok := val.(string); ok && s != "" {
				info.Paths = append(info.Paths, s)
			}
		}
	}
}

// extractContentField extracts content from Write/Edit tool args
func (e *Extractor) extractContentField(info *ExtractedInfo) {
	contentFields := []string{"content", "new_string", "text", "data"}

	for _, field := range contentFields {
		if val, ok := info.RawArgs[field]; ok {
			if s, ok := val.(string); ok && s != "" {
				info.Content = s
				return
			}
		}
	}
}

// tokenizeCommand splits a command string into tokens, respecting quotes
// It stops at pipe, semicolon, or && and skips redirect targets
func tokenizeCommand(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false
	skipRedirectTarget := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}

		if c == '\\' && !inSingleQuote {
			escaped = true
			continue
		}

		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}

		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		if (c == ' ' || c == '\t') && !inSingleQuote && !inDoubleQuote {
			if current.Len() > 0 {
				if !skipRedirectTarget {
					tokens = append(tokens, current.String())
				}
				skipRedirectTarget = false
				current.Reset()
			}
			continue
		}

		// Stop at pipe, semicolon, or && (we only process the first command)
		if !inSingleQuote && !inDoubleQuote {
			if c == '|' || c == ';' {
				break
			}
			if c == '&' && i+1 < len(cmd) && cmd[i+1] == '&' {
				break
			}
			// Handle redirection operators - skip the target
			if c == '>' || c == '<' {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
				// Skip >> or <<
				if i+1 < len(cmd) && cmd[i+1] == c {
					i++
				}
				// Mark that we should skip the next token (redirect target)
				skipRedirectTarget = true
				continue
			}
		}

		current.WriteByte(c)
	}

	if current.Len() > 0 && !skipRedirectTarget {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// hasWriteRedirection checks if command has > or >> redirection
func hasWriteRedirection(cmd string) bool {
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		if !inSingleQuote && !inDoubleQuote && c == '>' {
			// Make sure it's not &> or 2>&1 etc. - still a write
			return true
		}
	}

	return false
}

// extractRedirectTargets extracts file paths from shell redirections
func extractRedirectTargets(cmd string) []string {
	var paths []string
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		if !inSingleQuote && !inDoubleQuote && c == '>' {
			// Skip >> (append)
			if i+1 < len(cmd) && cmd[i+1] == '>' {
				i++
			}
			// Skip whitespace
			j := i + 1
			for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
				j++
			}
			// Extract the path
			if j < len(cmd) {
				path := extractNextToken(cmd[j:])
				if path != "" {
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

// extractNextToken extracts the next token from a string
func extractNextToken(s string) string {
	var result strings.Builder
	inSingleQuote := false
	inDoubleQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]

		if c == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if c == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		if (c == ' ' || c == '\t' || c == ';' || c == '|' || c == '&') && !inSingleQuote && !inDoubleQuote {
			break
		}

		result.WriteByte(c)
	}

	return result.String()
}

// extractHosts extracts hostnames/IPs from tokens (for network commands)
func extractHosts(tokens []string) []string {
	var hosts []string

	for _, token := range tokens {
		// Skip flags
		if strings.HasPrefix(token, "-") {
			continue
		}

		// Check if it looks like a URL
		if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
			host := extractHostFromURL(token)
			if host != "" {
				hosts = append(hosts, host)
			}
			continue
		}

		// Check if it looks like a host:port
		if strings.Contains(token, ":") && !strings.Contains(token, "/") {
			parts := strings.Split(token, ":")
			if len(parts) >= 1 && parts[0] != "" {
				hosts = append(hosts, parts[0])
			}
			continue
		}

		// Check if it looks like an IP or hostname (simple heuristic)
		if looksLikeHost(token) {
			hosts = append(hosts, token)
		}
	}

	return hosts
}

// extractHostFromURL extracts the host from a URL
func extractHostFromURL(url string) string {
	// Remove protocol
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}

	// Remove path
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	// Remove auth info (user:pass@host) - must be before port removal
	if idx := strings.Index(url, "@"); idx != -1 {
		url = url[idx+1:]
	}

	// Remove port
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

// looksLikeHost checks if a string looks like a hostname or IP
func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}

	// Check for IP address pattern
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		allDigits := true
		for _, part := range parts {
			for _, c := range part {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
		}
		if allDigits {
			return true
		}
	}

	// Check for hostname pattern (letters, digits, dots, hyphens)
	hasLetter := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if c != '.' && c != '-' && (c < '0' || c > '9') {
			return false
		}
	}

	return hasLetter && strings.Contains(s, ".")
}

// looksLikePath checks if a token starting with - might actually be a path
func looksLikePath(token string) bool {
	// Paths like ./-file or paths containing /
	return strings.HasPrefix(token, "./") || strings.Contains(token, "/")
}

// deduplicatePaths removes duplicate paths while preserving order
func deduplicatePaths(paths []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}
