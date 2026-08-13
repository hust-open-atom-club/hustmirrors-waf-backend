package echo

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	echov4 "github.com/labstack/echo/v4"

	"github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/adminui"
)

const adminUICSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func (s *Server) adminUIRedirect(c echov4.Context) error {
	return c.Redirect(http.StatusPermanentRedirect, "/admin/")
}

func (s *Server) adminUI(c echov4.Context) error {
	setAdminUISecurityHeaders(c)

	requested := strings.TrimPrefix(c.Param("*"), "/")
	if strings.HasPrefix(requested, "api/") {
		return echov4.NewHTTPError(http.StatusNotFound)
	}

	fileName := requested
	if fileName == "" {
		fileName = "index.html"
	}
	fileName = strings.TrimPrefix(path.Clean("/"+fileName), "/")

	data, err := fs.ReadFile(adminui.Files(), fileName)
	if err != nil {
		// Client-side routes have no extension and fall back to the SPA shell.
		// Missing static assets must remain a real 404 rather than receiving HTML.
		if path.Ext(fileName) != "" {
			return echov4.NewHTTPError(http.StatusNotFound)
		}
		fileName = "index.html"
		data, err = fs.ReadFile(adminui.Files(), fileName)
		if err != nil {
			return echov4.NewHTTPError(http.StatusNotFound)
		}
	}

	contentType := mime.TypeByExtension(path.Ext(fileName))
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}
	if fileName == "index.html" {
		c.Response().Header().Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(fileName, "assets/") {
		c.Response().Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		c.Response().Header().Set("Cache-Control", "public, max-age=3600")
	}
	return c.Blob(http.StatusOK, contentType, data)
}

func setAdminUISecurityHeaders(c echov4.Context) {
	h := c.Response().Header()
	h.Set("Content-Security-Policy", adminUICSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}
