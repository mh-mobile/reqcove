//go:build !darwin

package main

import "context"

// keepAwake is a no-op off macOS (--keep-awake is macOS's); servers rarely
// idle-sleep.
func keepAwake(context.Context, string) {}
