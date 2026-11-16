package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// keepAwake keeps the Mac from sleeping while reqcove runs, as mode says. It
// cannot stop sleep from closing the lid on battery or choosing Sleep; the
// iPhone then loses its exit node.
func keepAwake(ctx context.Context, mode string) {
	flag := caffeinateFlag(mode)
	if flag == "" {
		return
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/caffeinate", flag, "-w", fmt.Sprint(os.Getpid()))
	if err := cmd.Start(); err != nil {
		log.Printf("WARN: caffeinate: %v; the Mac may sleep while reqcove runs", err)
		return
	}
	go cmd.Wait()
}
