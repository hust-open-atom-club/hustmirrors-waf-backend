package matcher

import (
	"net/url"
	"strings"
)

// NormalizePath canonicalises a request path before protection matching.
//
// Protection is decided by suffix and regex, so any transformation that
// changes the tail of the string while still addressing the same file is a
// potential bypass. Observed against the extension matcher, all of these
// read as "not protected" while naming a .iso:
//
//	/ubuntu%2Eiso     percent-encoded dot
//	/ubuntu.iso/      trailing slash
//	/ubuntu.iso.      trailing dot
//	/ubuntu.iso       trailing space
//	/ubuntu.iso;x=1   path parameter
//	/ubuntu.iso\x00…  NUL truncation
//
// The shipped Nginx config decodes and normalises $uri before its own
// location regex runs, so most of these never reach the backend and the
// rest 404 on try_files. That makes this defence in depth rather than a
// live bypass - but the backend's is_protected also feeds the risk engine,
// and a deployment that fronts this service differently (or applies
// auth_request at location /) would have no such protection. A security
// decision should not depend on a normalisation step performed by
// somebody else's config.
//
// This is deliberately conservative: it only strips things that cannot
// change which file is addressed. It does not resolve ".." or collapse
// slashes, because those belong to the proxy and guessing at them here
// could disagree with what actually gets served.
func NormalizePath(path string) string {
	if path == "" {
		return ""
	}

	// Percent-decoding first: %2E must become "." before suffix matching.
	// Undecodable input is left as-is rather than rejected, so a malformed
	// escape cannot make a path silently unprotected.
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}

	// A NUL terminates the path for any C-based file layer downstream;
	// everything after it is not part of the name being requested.
	if i := strings.IndexByte(path, 0); i >= 0 {
		path = path[:i]
	}

	// Path parameters (RFC 3986 ";key=value") are not part of the segment
	// name. Only the final segment matters for suffix matching.
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if j := strings.IndexByte(path[i:], ';'); j >= 0 {
			path = path[:i+j]
		}
	} else if j := strings.IndexByte(path, ';'); j >= 0 {
		path = path[:j]
	}

	// Trailing slashes, dots and whitespace: filesystems and HTTP servers
	// routinely treat "/f.iso/", "/f.iso." and "/f.iso " as "/f.iso".
	path = strings.TrimRight(path, "/. \t")

	return path
}
