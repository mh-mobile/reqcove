//go:build !darwin

package main

// keepAwake is a no-op off macOS (--keep-awake is macOS's); servers rarely
// idle-sleep.
func keepAwake(string) (stop func()) { return func() {} }
