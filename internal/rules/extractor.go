package rules

import (
	"encoding/json"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ExtractedInfo contains paths and operation from a tool call
type ExtractedInfo struct {
	Operation     Operation
	Paths         []string
	Hosts         []string
	Command       string // Raw command string (for Bash tool)
	Content       string // Content being written (for Write/Edit tools)
	RawArgs       map[string]any
	Evasive       bool   // true if command uses shell tricks that prevent static analysis
	EvasiveReason string // human-readable reason for evasion detection
}

// parsedCommand represents a single command extracted from a shell AST.
type parsedCommand struct {
	Name       string
	Args       []string
	HasSubst   bool     // true if any arg contains $() or backticks
	RedirPaths []string // paths from redirections (>, >>)
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
	SkipFlags    []string // flags followed by non-path values (-n, --count)
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
	} else {
		info.Content = string(args)
	}

	// Normalize tool name for comparison
	toolLower := strings.ToLower(toolName)

	switch toolLower {
	case "bash", "exec":
		e.extractBashCommand(&info)
	case "read", "read_file":
		e.extractReadTool(&info)
	case "write", "write_file":
		e.extractWriteTool(&info)
	case "edit":
		e.extractEditTool(&info)
	case "webfetch", "web_fetch", "web_search", "browser":
		e.extractWebFetchTool(&info)
	default:
		// Unknown tool (including MCP): only extract generic paths
		// Content-only rules will handle matching via raw JSON
		e.extractGenericPaths(&info)
	}

	return info
}

// extractBashCommand parses a bash command and extracts paths/operation.
// Uses the mvdan.cc/sh AST parser to analyze ALL commands in pipelines,
// chains (&&, ||, ;), and subshells. Falls back to the legacy tokenizer
// if the AST parser fails (e.g., incomplete or malformed commands from LLM).
func (e *Extractor) extractBashCommand(info *ExtractedInfo) {
	cmdRaw, ok := info.RawArgs["command"]
	if !ok {
		return
	}

	cmd, ok := cmdRaw.(string)
	if !ok {
		return
	}

	// Store the raw command for advanced rule matching (match.command regex)
	info.Command = cmd

	// Empty/whitespace-only commands are harmless
	if strings.TrimSpace(cmd) == "" {
		return
	}

	// Parse using full Bash AST parser (handles pipelines, &&, ||, subshells)
	if parsed := parseShellCommands(cmd); len(parsed) > 0 {
		e.extractFromParsedCommands(info, parsed)
		return
	}

	// AST parse failed (e.g., severely malformed command) — mark as evasive
	info.Evasive = true
	info.EvasiveReason = "command could not be parsed for security analysis"
}

// extractFromParsedCommands processes all commands from the shell AST parser.
// Merges paths, hosts, and operations from every command in the pipeline/chain.
func (e *Extractor) extractFromParsedCommands(info *ExtractedInfo, commands []parsedCommand) {
	for _, pc := range commands {
		// Check for command substitution evasion
		if pc.HasSubst {
			info.Evasive = true
			info.EvasiveReason = "command contains shell substitution ($() or backticks) which prevents static analysis"
		}

		// Resolve the actual command name and args, skipping wrappers like sudo/env
		cmdName, args := e.resolveCommand(pc.Name, pc.Args)

		// Look up in command database
		cmdInfo, found := e.commandDB[cmdName]
		if found {
			// Use the most dangerous operation
			if operationPriority(cmdInfo.Operation) > operationPriority(info.Operation) {
				info.Operation = cmdInfo.Operation
			}
			// Extract paths from positional arguments
			e.extractPathsFromArgs(info, args, cmdInfo)

			// For network commands, extract hosts from all args
			if cmdInfo.Operation == OpNetwork {
				info.Hosts = append(info.Hosts, extractHosts(args)...)
			}
		}

		// Add redirect target paths (always a write)
		if len(pc.RedirPaths) > 0 {
			info.Paths = append(info.Paths, pc.RedirPaths...)
			if operationPriority(OpWrite) > operationPriority(info.Operation) {
				info.Operation = OpWrite
			}
		}
	}

	// Deduplicate
	info.Paths = deduplicateStrings(info.Paths)
	info.Hosts = deduplicateStrings(info.Hosts)
}

// resolveCommand skips wrapper commands (sudo, env, time, nice) and returns
// the actual command name and its arguments.
func (e *Extractor) resolveCommand(name string, args []string) (string, []string) {
	// Strip path prefix (e.g., /usr/bin/cat → cat)
	cmdName := name
	if idx := strings.LastIndex(cmdName, "/"); idx != -1 {
		cmdName = cmdName[idx+1:]
	}

	wrappers := map[string]bool{"sudo": true, "env": true, "time": true, "nice": true}

	// Walk through wrapper commands
	for wrappers[cmdName] && len(args) > 0 {
		// Skip flags of the wrapper (e.g., sudo -u root)
		i := 0
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			i++
			// Skip flag value if it's a separate arg (e.g., sudo -u root)
			if i < len(args) && !strings.HasPrefix(args[i], "-") &&
				(i > 0 && (args[i-1] == "-u" || args[i-1] == "-g")) {
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

// extractPathsFromArgs extracts paths from parsed command arguments using the command database.
func (e *Extractor) extractPathsFromArgs(info *ExtractedInfo, args []string, cmdInfo CommandInfo) {
	positionalIdx := 0
	skipNext := false

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
		isSkipFlag := false
		for _, flag := range cmdInfo.SkipFlags {
			if arg == flag {
				isSkipFlag = true
				break
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
		for _, pathIdx := range cmdInfo.PathArgIndex {
			if positionalIdx == pathIdx {
				info.Paths = append(info.Paths, arg)
				break
			}
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

// parseShellCommands parses a shell command string using a full Bash AST parser
// (mvdan.cc/sh) and extracts ALL individual commands, including those in
// pipelines (|), chains (&&, ||, ;), subshells, and command substitutions ($()).
// Returns nil if parsing fails, in which case the caller should fall back to
// the AST parser.
func parseShellCommands(cmd string) []parsedCommand {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil // parse failed — fall back to legacy tokenizer
	}

	var commands []parsedCommand
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				return true
			}
			pc := parsedCommand{
				Name: wordToString(n.Args[0]),
			}
			for _, w := range n.Args[1:] {
				arg := wordToString(w)
				pc.Args = append(pc.Args, arg)
				// Check for command substitution in arguments
				if wordHasSubst(w) {
					pc.HasSubst = true
				}
			}
			commands = append(commands, pc)

		case *syntax.Redirect:
			// Extract redirect target paths (>, >>)
			if n.Op == syntax.RdrOut || n.Op == syntax.AppOut ||
				n.Op == syntax.RdrAll || n.Op == syntax.AppAll {
				path := wordToString(n.Word)
				if path != "" && len(commands) > 0 {
					last := &commands[len(commands)-1]
					last.RedirPaths = append(last.RedirPaths, path)
				}
			}
		}
		return true
	})

	return commands
}

// wordToString extracts the literal string value from a syntax.Word.
// For words containing expansions ($VAR, $(), etc.), it reconstructs
// the string as it would appear in the source.
func wordToString(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		case *syntax.ParamExp:
			// Reconstruct $VAR or ${VAR}
			if p.Param != nil {
				if p.Short {
					sb.WriteString("$")
					sb.WriteString(p.Param.Value)
				} else {
					sb.WriteString("${")
					sb.WriteString(p.Param.Value)
					sb.WriteString("}")
				}
			}
		case *syntax.CmdSubst:
			// Mark as $(...) — caller detects via wordHasSubst
			sb.WriteString("$(…)")
		}
	}
	return sb.String()
}

// wordHasSubst checks if a syntax.Word contains command substitution ($() or backticks)
// or process substitution (<() or >()).
func wordHasSubst(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch part.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			return true
		case *syntax.DblQuoted:
			dq := part.(*syntax.DblQuoted)
			for _, inner := range dq.Parts {
				switch inner.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					return true
				}
			}
		}
	}
	return false
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
