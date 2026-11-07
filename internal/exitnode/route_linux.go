package exitnode

import (
	"os/exec"
	"strings"
)

// routeDevice returns the interface the host routes ip through ("" if unknown).
func routeDevice(ip string) string {
	out, err := exec.Command("ip", "route", "get", ip).Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}
