package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// keepAwake keeps the Mac from sleeping while reqcove runs, as mode says, until
// stop. It cannot stop sleep from closing the lid on battery or choosing Sleep;
// the iPhone then loses its exit node. stop ends caffeinate and waits for it:
// a restart keeps run's pid (exec), which caffeinate -w would wait on for good.
func keepAwake(mode string) (stop func()) {
	flag := caffeinateFlag(mode)
	if flag == "" {
		return func() {}
	}
	cmd := exec.Command("/usr/bin/caffeinate", flag, "-w", fmt.Sprint(os.Getpid()))
	if err := cmd.Start(); err != nil {
		log.Printf("WARN: caffeinate: %v; the Mac may sleep while reqcove runs", err)
		return func() {}
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	return func() { cmd.Process.Kill(); <-done }
}
