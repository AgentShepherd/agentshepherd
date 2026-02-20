// Package fileutil provides secure file operations that enforce proper
// access control on both Unix and Windows.
//
// On Unix, standard file mode bits (0600, 0700) are enforced.
// On Windows, DACL-based ACLs restrict access to the current user only,
// since Unix permission bits are silently ignored by the Windows kernel.
package fileutil
