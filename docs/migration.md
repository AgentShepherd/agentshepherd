# Migration Guide

## Pre-compilation Validation (v0.x → v0.y)

### What Changed

Rule patterns (regex, glob) are now validated and pre-compiled at rule load time instead of at runtime. This is more secure and faster, but it means rules with invalid patterns that previously "worked" (by silently failing to match) will now be detected and handled.

**Before:** Invalid patterns silently returned `false` at runtime. All rules loaded regardless of pattern validity.

**After:** Patterns are validated at insert time. Invalid builtin rules fail hard (startup error). Invalid user rules are skipped with a warning, and the remaining valid rules still load.

### Impact

- **Builtin rules:** No impact. All builtin rules have been validated.
- **User rules:** Rules with invalid patterns (malformed regex, invalid globs, null bytes, control characters) will be **skipped** instead of silently failing. Other valid rules in the same file continue to load.

### How to Check Your Rules

Run the linter before upgrading. It now catches all patterns that would be rejected at load time:

```bash
# Lint all rule files
crust lint-rules

# Lint a specific file
crust lint-rules /path/to/rules.yaml

# Validate via API
curl -X POST http://localhost:9090/api/crust/rules/validate \
  -d @rules.yaml
```

The linter reports per-rule results including pattern compilation errors:

```
$ crust lint-rules
Linting builtin rules...
  No issues found.
Linting user rules...
  ✗ [error] bad-regex: patterns - rule "bad-regex": match.path regex "re:(?P<invalid": error parsing regexp
  ✗ [error] null-byte: patterns - rule "null-byte" block.paths[0]: pattern contains null byte at position 5
  ⚠ [warning] broad-rule: block.paths[0] - very short pattern may match too broadly
```

### Validation API Changes

The `POST /api/crust/rules/validate` endpoint now performs full pattern compilation and returns per-rule results:

```json
{
  "valid": false,
  "rules": [
    {"name": "good-rule", "valid": true},
    {"name": "bad-regex", "valid": false, "error": "match.path regex \"re:(?P<invalid\": error parsing regexp: ..."}
  ]
}
```

### Common Pattern Issues

| Issue | Example | Fix |
|-------|---------|-----|
| Invalid regex | `re:(?P<invalid` | Fix the regex syntax |
| Malformed glob bracket | `[unclosed` | Close the bracket: `[unclosed]` |
| Null bytes | `/path\x00bad` | Remove null bytes from pattern |
| Control characters | `/path\x01bad` | Remove control characters (tabs are allowed) |
| Regex too long | `re:` + 4096+ chars | Simplify the regex (max 4096 chars) |

### Behavior Summary

| Rule Source | Invalid Pattern Behavior |
|-------------|------------------------|
| Builtin | Startup fails (must be fixed) |
| User | Rule skipped with warning, others continue |
| Test (`NewTestEngine`) | Returns error (tests should catch bad patterns) |
| Validate API | Reports error per-rule, never skips silently |
| Lint | Reports error as lint issue |
