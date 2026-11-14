package main

import "golang.org/x/sys/unix"

// ttyFlushInput drops the terminal's input typed and not read yet (tcflush(fd, TCIFLUSH)).
func ttyFlushInput(fd int) error { return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH) }
