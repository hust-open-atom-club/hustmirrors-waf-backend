package config

import "time"

// A bad literal here is a programming bug and will panic at startup.
func parseDur(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic("config: invalid default duration literal: " + s)
	}
	return d
}
