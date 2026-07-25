package awconfig

import "errors"

var ErrLockUnavailable = errors.New("lock is held by another process")
