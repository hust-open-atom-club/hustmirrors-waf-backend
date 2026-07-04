package auth

// AuthRequest carries the per-request data extracted from Nginx headers.
type AuthRequest struct {
	OriginalURI    string
	OriginalMethod string
	OriginalArgs   string
	RealIP         string
	ForwardedFor   string
	UserAgent      string
	// OriginalRange is the client's Range header, forwarded by Nginx as
	// X-Original-Range. May be empty when Nginx is not configured to forward it.
	OriginalRange string
}
