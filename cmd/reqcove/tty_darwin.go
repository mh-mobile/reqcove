package main

import "golang.org/x/sys/unix"

// ttyFlushInput drops the terminal's input typed and not read yet
// (tcflush(fd, TCIFLUSH): TIOCFLUSH with FREAD, 1, on macOS).
func ttyFlushInput(fd int) error { return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, 1) }
