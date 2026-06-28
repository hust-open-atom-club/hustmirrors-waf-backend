package version

import "fmt"

// Values are injected via -ldflags at build time:
//
//	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Version=dev \
//	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.Commit=none \
//	-X github.com/hust-open-atom-club/hustmirrors-waf-backend/internal/version.BuildTime=...
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: goVersion(),
	}
}

func (i Info) String() string {
	return fmt.Sprintf("%s (commit=%s, built=%s, go=%s)", i.Version, i.Commit, i.BuildTime, i.GoVersion)
}
