package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// keepAwake stops idle sleep while reqcove runs. It cannot stop sleep from
// closing the lid or choosing Sleep; the iPhone then loses its exit node.
func keepAwake(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "/usr/bin/caffeinate", "-i", "-w", fmt.Sprint(os.Getpid()))
	if err := cmd.Start(); err != nil {
		log.Printf("WARN: caffeinate: %v; the Mac may sleep while reqcove runs", err)
		return
	}
	go cmd.Wait()
}
