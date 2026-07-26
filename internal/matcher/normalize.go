package matcher

import (
	"net/url"
	"strings"
)

// NormalizePath canonicalises a request path before protection matching.
//
// Protection is decided by suffix and regex, so anything that changes the
// tail while still naming the same file is a bypass. These all read as
// "not protected" for a .iso: /ubuntu%2Eiso, /ubuntu.iso/, /ubuntu.iso.,
// "/ubuntu.iso ", /ubuntu.iso;x=1, /ubuntu.iso\x00.txt
//
// The shipped Nginx config normalises $uri first, so most never reach us.
// But is_protected also feeds the risk engine, and a different proxy setup
// has no such guarantee.
//
// Only strips what cannot change which file is addressed. ".." and
// duplicate slashes are left to the proxy.
func NormalizePath(path string) string {
	if path == "" {
		return ""
	}

	// %2E must become "." before suffix matching. Malformed escapes are
	// left alone so they can't become silently unprotected.
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}

	// NUL terminates the path for any C-based layer downstream.
	if i := strings.IndexByte(path, 0); i >= 0 {
		path = path[:i]
	}

	// Path params (RFC 3986 ";k=v") aren't part of the segment name, and
	// only the last segment matters for suffix matching.
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		if j := strings.IndexByte(path[i:], ';'); j >= 0 {
			path = path[:i+j]
		}
	} else if j := strings.IndexByte(path, ';'); j >= 0 {
		path = path[:j]
	}

	// "/f.iso/", "/f.iso." and "/f.iso " all resolve to /f.iso downstream.
	return strings.TrimRight(path, "/. \t")
}
