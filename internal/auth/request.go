package auth

// AuthRequest carries the per-request data extracted from Nginx headers.
//
// No ForwardedFor field on purpose: IP decisions run on RealIP alone, and a
// second IP source here would invite a caller to disagree with /whoami.
type AuthRequest struct {
	OriginalURI    string
	OriginalMethod string
	OriginalArgs   string
	RealIP         string
	UserAgent      string
	// OriginalRange is the client's Range header, forwarded by Nginx as
	// X-Original-Range. May be empty when Nginx is not configured to forward it.
	OriginalRange string
}
