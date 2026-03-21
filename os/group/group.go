// Copyright (c) 2026 Joseph Naegele. See LICENSE file.

// Package group allows group lookups by name or id.
package group

var implemented = true // set to false by lookup_stubs.go's init

// Group represents a Unix group. Gid contains the decimal group ID as a string.
type Group struct {
	Gid      string
	Name     string
	Password string
	Members  []string
}

// UnknownGroupIdError is returned by LookupId when
// a group cannot be found.
type UnknownGroupIdError int

func (e UnknownGroupIdError) Error() string {
	return "unknown group id"
}

// UnknownGroupError is returned by Lookup when
// a group cannot be found
type UnknownGroupError string

func (e UnknownGroupError) Error() string {
	return "unknown group name"
}
