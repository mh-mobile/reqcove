package exitnode

import (
	"os/exec"
	"strings"
)

// routeDevice returns the interface the host routes ip through ("" if unknown).
func routeDevice(ip string) string {
	out, err := exec.Command("route", "-n", "get", ip).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "interface" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
