package main

// caffeinateFlag is caffeinate's assertion for --keep-awake: always stops
// idle sleep, on battery too (-i); ac stops system sleep on AC power only
// (-s, as `pmset -c sleep 0` would); never holds none. Other apps' assertions
// add up with it: `pmset -g assertions` lists them all.
func caffeinateFlag(mode string) string {
	switch mode {
	case "ac":
		return "-s"
	case "never":
		return ""
	}
	return "-i"
}
