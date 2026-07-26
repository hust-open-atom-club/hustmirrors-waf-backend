package clock

import "time"

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func New() Clock { return realClock{} }

func (realClock) Now() time.Time { return time.Now() }

// Fake is a deterministic Clock whose time is controlled by the test.
type Fake struct{ t time.Time }

func NewFake() *Fake { return &Fake{} }

func (f *Fake) Now() time.Time          { return f.t }
func (f *Fake) Set(t time.Time)         { f.t = t }
func (f *Fake) Advance(d time.Duration) { f.t = f.t.Add(d) }
