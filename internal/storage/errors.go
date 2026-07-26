package storage

import "errors"

var ErrNotFound = errors.New("storage: not found")

var ErrClosed = errors.New("storage: closed")
