//go:build !darwin

package main

import "context"

// keepAwake is a no-op off macOS; servers rarely idle-sleep.
func keepAwake(context.Context) {}
