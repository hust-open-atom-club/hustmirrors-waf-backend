package adminui

import (
	"embed"
	"io/fs"
)

// dist contains the production Vite build. It is committed so normal Go
// builds do not require Node.js or npm on the deployment host.
//
//go:embed dist
var assets embed.FS

// Files returns the embedded distribution with dist/ removed from paths.
func Files() fs.FS {
	sub, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
