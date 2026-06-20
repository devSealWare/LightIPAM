package store

import "errors"

var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when creating a record that violates a uniqueness
// rule (e.g. a custom field with a name already defined for that entity type).
var ErrDuplicate = errors.New("already exists")
