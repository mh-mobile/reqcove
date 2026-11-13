package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
)

// withSystemProxy, on macOS with the local proxy on, points the system's web
// proxies at it for as long as f runs, and puts them back after, however f ends.
func withSystemProxy(state string, on bool, f func() error) error {
	if !on || runtime.GOOS != "darwin" {
		return f()
	}
	if err := pointSystemProxy(state); err != nil {
		log.Printf("WARN: the system's web proxies are left as they are (%v). The local proxy runs all the same, for apps pointed at it", err)
		return f()
	}
	log.Printf("this computer's web proxies point at the local proxy until reqcove stops; the LAN, the tailnet and this computer bypass it")
	defer func() {
		log.Printf("putting the system's web proxies back (a few seconds; no need to press Ctrl-C again)")
		if err := restoreSystemProxy(state); err != nil {
			log.Printf("WARN: could not put the system's web proxies back: %v. System Settings, Network, Details, Proxies; or %s", err, withState("reqcove cleanup", state))
		}
	}()
	return f()
}

// The local proxy (--local-proxy): on macOS, run points the system's web
// proxies at it while it runs, as Charles and Proxyman do, and puts them back
// when it stops. What they were is kept in the state directory, so a run that
// died puts them back at the next start or with `reqcove cleanup`.

const localProxyPort = 8082

// networksetup runs macOS's networksetup; tests replace it. It can say
// "** Error" with no failing exit status: that counts as failing too.
var networksetup = func(args ...string) (string, error) {
	out, err := nsCommand(args...).CombinedOutput()
	return string(out), nsError(string(out), err)
}

// nsCommand runs networksetup in its own process group: a second Ctrl-C in
// the terminal, while run puts the proxies back, must not stop it midway.
func nsCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("networksetup", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func nsError(out string, err error) error {
	if err == nil && strings.Contains(out, "** Error") {
		return errors.New(strings.TrimSpace(out))
	}
	return err
}

// bypass is what never goes through the local proxy: this computer, the LAN and
// the tailnet, by address or by these names, go direct. A name that resolves to
// the LAN, a VPN or the tailnet does reach the proxy, which lets it on (only
// this computer and link-local are refused: decideLocal), so a browser here
// does not see where such a name leads (DNS rebinding; docs/SECURITY.md).
var bypass = []string{"localhost", "::1", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254/16", "100.64.0.0/10", "fd7a:115c:a1e0::/48", "*.local", "*.ts.net"}

// webProxy is one service's web proxy (HTTP) or secure web proxy (HTTPS).
type webProxy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    string `json:"port"`
}

type savedProxy struct {
	Service string   `json:"service"`
	Web     webProxy `json:"web"`
	Secure  webProxy `json:"secure"`
	Bypass  []string `json:"bypass"`
}

var ours = webProxy{Enabled: true, Server: "127.0.0.1", Port: fmt.Sprint(localProxyPort)}

func savedProxyFile(state string) string { return filepath.Join(state, "system-proxy.json") }

// services are the enabled network services ("Wi-Fi", "Ethernet"...).
func services() ([]string, error) {
	out, err := networksetup("-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("networksetup -listallnetworkservices: %v: %s", err, strings.TrimSpace(out))
	}
	var names []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") { // a header line; "*" marks a disabled service
			continue
		}
		names = append(names, line)
	}
	return names, nil
}

func getProxy(kind, service string) (webProxy, error) {
	out, err := networksetup("-get"+kind, service)
	if err != nil {
		return webProxy{}, fmt.Errorf("networksetup -get%s %q: %v", kind, service, err)
	}
	var p webProxy
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch v = strings.TrimSpace(v); strings.TrimSpace(k) {
		case "Enabled":
			p.Enabled = v == "Yes"
		case "Server":
			p.Server = v
		case "Port":
			p.Port = v
		}
	}
	if p.Server == ours.Server && p.Port == ours.Port && !p.Enabled {
		// Turned off with reqcove's address left in it, as builds before
		// 17ec7a8 put an empty proxy back: not pointed at reqcove; put back off and empty.
		return webProxy{}, nil
	}
	if p.Server == ours.Server && p.Port == ours.Port {
		// Pointed at a reqcove already (one with other state, running or not):
		// that one holds what to put back, so this one must not save over it.
		return p, fmt.Errorf("%s's proxy already points at 127.0.0.1:%d, from another reqcove run (another --state): stop it, or run its `reqcove cleanup --state …`", service, localProxyPort)
	}
	return p, nil
}

func getBypass(service string) ([]string, error) {
	out, err := networksetup("-getproxybypassdomains", service)
	if err != nil {
		return nil, fmt.Errorf("networksetup -getproxybypassdomains %q: %v", service, err)
	}
	var list []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "There aren't any") {
			list = append(list, line)
		}
	}
	return list, nil
}

func ns(args ...string) error {
	if out, err := networksetup(args...); err != nil {
		return fmt.Errorf("networksetup %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

// setProxy sets one proxy as p has it: a disabled one keeps its server and
// port, or is emptied when it had none ("" and 0 empty it: tried on macOS 27).
func setProxy(kind, service string, p webProxy) error {
	server, port := p.Server, p.Port
	if server == "" || port == "" || port == "0" {
		server, port = "", "0"
	}
	if err := ns("-set"+kind, service, server, port); err != nil { // this also turns it on
		return err
	}
	if !p.Enabled {
		return ns("-set"+kind+"state", service, "off")
	}
	return nil
}

func setBypass(service string, list []string) error {
	if len(list) == 0 {
		list = []string{"Empty"}
	}
	return ns(append([]string{"-setproxybypassdomains", service}, list...)...)
}

// pointSystemProxy saves the web proxies of every enabled service, then points
// them at the local proxy. It saves before it changes anything.
func pointSystemProxy(state string) error {
	if _, err := os.Stat(savedProxyFile(state)); err == nil {
		// Settings saved by an earlier run were not put back: saving again would lose them.
		return fmt.Errorf("the settings an earlier run saved in %s are not put back yet", savedProxyFile(state))
	}
	names, err := services()
	if err != nil {
		return err
	}
	var saved []savedProxy
	for _, s := range names {
		web, err := getProxy("webproxy", s)
		if err != nil {
			return err
		}
		secure, err := getProxy("securewebproxy", s)
		if err != nil {
			return err
		}
		by, err := getBypass(s)
		if err != nil {
			return err
		}
		saved = append(saved, savedProxy{s, web, secure, by})
	}
	b, _ := json.Marshal(saved)
	if err := os.WriteFile(savedProxyFile(state), b, 0o600); err != nil {
		return err
	}
	for _, s := range saved {
		by := slices.Clone(s.Bypass)
		for _, b := range bypass {
			if !slices.Contains(by, b) {
				by = append(by, b)
			}
		}
		for _, err := range []error{setBypass(s.Service, by), setProxy("webproxy", s.Service, ours), setProxy("securewebproxy", s.Service, ours)} {
			if err != nil {
				restoreSystemProxy(state)
				return err
			}
		}
	}
	return nil
}

// restoreSystemProxy puts back what pointSystemProxy saved, if anything, and
// forgets it. Nothing saved: nothing to do.
func restoreSystemProxy(state string) error {
	b, err := os.ReadFile(savedProxyFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var saved []savedProxy
	if err := json.Unmarshal(b, &saved); err != nil {
		return err
	}
	var errs []error
	for _, s := range saved {
		for _, err := range []error{setProxy("webproxy", s.Service, s.Web), setProxy("securewebproxy", s.Service, s.Secure), setBypass(s.Service, s.Bypass)} {
			if err != nil && strings.Contains(err.Error(), "Unable to find item") {
				break // the service is gone (a VPN's, a USB adapter's): nothing to put back
			}
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		// The file stays: the next start or cleanup tries again.
		return fmt.Errorf("%w (once they are back, by hand in System Settings, Network, Details, Proxies, delete %s)", err, savedProxyFile(state))
	}
	return os.Remove(savedProxyFile(state))
}

// xcrun runs Xcode's xcrun; tests replace it.
var xcrun = func(args ...string) (string, error) {
	out, err := exec.Command("xcrun", args...).CombinedOutput()
	return string(out), err
}

// trustInSimulators adds the CA to every booted iOS Simulator, returning their
// names. No Xcode, or none booted: none.
func trustInSimulators(caPEM string) ([]string, error) {
	out, err := xcrun("simctl", "list", "devices", "booted", "-j")
	if err != nil {
		return nil, nil // no Xcode here
	}
	var list struct {
		Devices map[string][]struct {
			UDID, Name, State string
		}
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("simctl list: %v", err)
	}
	var done []string
	for _, devs := range list.Devices {
		for _, d := range devs {
			if d.State != "Booted" {
				continue
			}
			if out, err := xcrun("simctl", "keychain", d.UDID, "add-root-cert", caPEM); err != nil {
				return done, fmt.Errorf("simctl keychain %s add-root-cert: %v: %s", d.Name, err, strings.TrimSpace(out))
			}
			done = append(done, d.Name)
		}
	}
	return done, nil
}

// security runs macOS's security tool; tests replace it. Its error is its exit status.
var security = func(args ...string) error {
	return exec.Command("security", args...).Run()
}

const loginKeychain = "~/Library/Keychains/login.keychain-db"

// macTrusts reports whether this Mac trusts the CA in pem for TLS servers, as
// its browsers would (-l: the certificate is a CA, -L -R offline: no network,
// no prompt). Only on macOS.
func macTrusts(pem string) bool {
	return runtime.GOOS == "darwin" && security("verify-cert", "-c", pem, "-l", "-p", "ssl", "-L", "-R", "offline", "-q") == nil
}

// macTrustCommand trusts the CA for TLS only, for this user (macOS asks for the password).
func macTrustCommand(pem string) string {
	return "security add-trusted-cert -r trustRoot -p ssl -k " + loginKeychain + " " + shellWord(pem)
}

// macUntrustCommand removes the CA, by its fingerprint, and the trust in it.
func macUntrustCommand(sha256 string) string {
	return "security delete-certificate -t -Z " + strings.ReplaceAll(sha256, ":", "") + " " + loginKeychain
}
