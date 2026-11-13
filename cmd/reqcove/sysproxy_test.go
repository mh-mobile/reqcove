package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeNetworksetup keeps proxies and bypass lists per service and answers like
// networksetup (formats as macOS 27 prints them).
func fakeNetworksetup(t *testing.T, proxies map[string]webProxy, failSet string) *[]string {
	t.Helper()
	var calls []string
	bypasses := map[string][]string{"Wi-Fi": {"*.local", "169.254/16"}}
	old := networksetup
	t.Cleanup(func() { networksetup = old })
	networksetup = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		cmd := args[0]
		if len(args) > 1 && args[1] != "Wi-Fi" && args[1] != "USB LAN" {
			return "** Error: Unable to find item in network database.\n", errors.New("exit status 8")
		}
		switch {
		case cmd == "-listallnetworkservices":
			return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB LAN\n*Bluetooth PAN\n", nil
		case cmd == "-getproxybypassdomains":
			if b := bypasses[args[1]]; len(b) > 0 {
				return strings.Join(b, "\n") + "\n", nil
			}
			return "There aren't any bypass domains set on " + args[1] + ".\n", nil
		case strings.HasPrefix(cmd, "-get"):
			p := proxies[strings.TrimPrefix(cmd, "-get")+"|"+args[1]]
			on, port := "No", p.Port
			if p.Enabled {
				on = "Yes"
			}
			if port == "" {
				port = "0"
			}
			return "Enabled: " + on + "\nServer: " + p.Server + "\nPort: " + port + "\nAuthenticated Proxy Enabled: 0\n", nil
		case failSet != "" && strings.Contains(strings.Join(args, " "), failSet):
			return "", errors.New("exit status 1")
		case cmd == "-setproxybypassdomains":
			if args[2] == "Empty" {
				delete(bypasses, args[1])
			} else {
				bypasses[args[1]] = args[2:]
			}
			proxies["bypass|"+args[1]] = webProxy{Server: strings.Join(bypasses[args[1]], ",")}
		case strings.HasSuffix(cmd, "state"): // turns it off, keeping the server and port
			k := strings.TrimSuffix(strings.TrimPrefix(cmd, "-set"), "state") + "|" + args[1]
			p := proxies[k]
			p.Enabled = false
			proxies[k] = p
		default: // "" and 0 empty it, as on macOS 27
			p := webProxy{true, args[2], args[3]}
			if p.Port == "0" {
				p.Port = ""
			}
			proxies[strings.TrimPrefix(cmd, "-set")+"|"+args[1]] = p
		}
		return "", nil
	}
	return &calls
}

// run points every enabled service's web proxies at the local proxy, saving
// them first; stopping puts back exactly what was there.
func TestSystemProxy(t *testing.T) {
	state := t.TempDir()
	corp := webProxy{true, "proxy.corp", "3128"}
	off := webProxy{false, "old.corp", "8080"} // turned off, its server kept
	proxies := map[string]webProxy{"webproxy|Wi-Fi": corp, "securewebproxy|Wi-Fi": corp, "webproxy|USB LAN": off}
	calls := fakeNetworksetup(t, proxies, "")
	if err := pointSystemProxy(state); err != nil {
		t.Fatal(err)
	}
	if by := proxies["bypass|Wi-Fi"].Server; !strings.HasPrefix(by, "*.local,169.254/16,localhost,::1,127.0.0.0/8") || !strings.Contains(by, "192.168.0.0/16") || !strings.Contains(by, "100.64.0.0/10") || !strings.Contains(by, "fd7a:115c:a1e0::/48") {
		t.Errorf("bypass: %s", by)
	}
	ours := webProxy{true, "127.0.0.1", "8082"}
	for _, k := range []string{"webproxy|Wi-Fi", "securewebproxy|Wi-Fi", "webproxy|USB LAN", "securewebproxy|USB LAN"} {
		if proxies[k] != ours {
			t.Errorf("%s: %+v", k, proxies[k])
		}
	}
	if slices.ContainsFunc(*calls, func(c string) bool { return strings.Contains(c, "Bluetooth") }) {
		t.Error("a disabled service was touched")
	}
	if err := restoreSystemProxy(state); err != nil {
		t.Fatal(err)
	}
	if proxies["webproxy|Wi-Fi"] != corp || proxies["securewebproxy|Wi-Fi"] != corp || proxies["webproxy|USB LAN"] != off || proxies["securewebproxy|USB LAN"] != (webProxy{}) {
		t.Errorf("not put back: %+v", proxies)
	}
	if proxies["bypass|Wi-Fi"].Server != "*.local,169.254/16" || proxies["bypass|USB LAN"].Server != "" {
		t.Errorf("bypass not put back: %q %q", proxies["bypass|Wi-Fi"].Server, proxies["bypass|USB LAN"].Server)
	}
	if _, err := os.Stat(savedProxyFile(state)); !os.IsNotExist(err) {
		t.Error("the saved settings stayed after they were put back")
	}
	if err := restoreSystemProxy(state); err != nil { // nothing saved: nothing to do
		t.Error(err)
	}
}

// A change that fails midway puts back what was already changed.
func TestSystemProxyFailsBack(t *testing.T) {
	for _, fail := range []string{"-setwebproxy USB LAN 127.0.0.1", "-setsecurewebproxy USB LAN 127.0.0.1"} {
		state := t.TempDir()
		proxies := map[string]webProxy{}
		fakeNetworksetup(t, proxies, fail)
		if err := pointSystemProxy(state); err == nil {
			t.Fatal("no error")
		}
		if proxies["webproxy|Wi-Fi"].Enabled || proxies["securewebproxy|Wi-Fi"].Enabled {
			t.Errorf("%s: left pointed at reqcove: %+v", fail, proxies)
		}
	}
}

// The CA goes into each booted Simulator, not the others.
func TestTrustInSimulators(t *testing.T) {
	var added []string
	old := xcrun
	defer func() { xcrun = old }()
	xcrun = func(args ...string) (string, error) {
		if args[1] == "list" {
			return `{"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-27-0":[{"udid":"U1","name":"iPhone 17","state":"Booted"},{"udid":"U2","name":"iPad Air","state":"Shutdown"}]}}`, nil
		}
		added = append(added, strings.Join(args, " "))
		return "", nil
	}
	got, err := trustInSimulators("/s/ca.pem")
	if err != nil || !slices.Equal(got, []string{"iPhone 17"}) || !slices.Equal(added, []string{"simctl keychain U1 add-root-cert /s/ca.pem"}) {
		t.Errorf("%v %v %v", got, added, err)
	}
	xcrun = func(...string) (string, error) { return "", errors.New("no xcrun") }
	if got, err := trustInSimulators("/s/ca.pem"); got != nil || err != nil {
		t.Errorf("without Xcode: %v %v", got, err)
	}
}

// --local-proxy alone is enough to start: no --device needed.
func TestLocalProxyWithoutDevice(t *testing.T) {
	err := run(context.Background(), []string{"--local-proxy", "--allow-hosts", "api.example.com", "--state", t.TempDir(), "--uvx", "/nonexistent/uvx"})
	if err == nil || strings.Contains(err.Error(), "--device is required") {
		t.Errorf("got %v", err)
	}
}

// Settings left pointed at reqcove by a run that died go back at the next
// start, and with cleanup, but not while a run holds the state.
func TestLeftSystemProxyGoesBack(t *testing.T) {
	corp := webProxy{true, "proxy.corp", "3128"}
	for _, how := range []string{"run", "cleanup", "cleanup while running"} {
		state := t.TempDir()
		if unlock, err := openState(state); err != nil {
			t.Fatal(err)
		} else {
			unlock()
		}
		proxies := map[string]webProxy{"webproxy|Wi-Fi": corp, "securewebproxy|Wi-Fi": corp}
		fakeNetworksetup(t, proxies, "")
		if err := pointSystemProxy(state); err != nil { // the run that died
			t.Fatal(err)
		}
		switch how {
		case "run":
			// Any run puts them back: without --local-proxy, which wants 8082 free first.
			run(context.Background(), []string{"--device", "phone", "--allow-hosts", "api.example.com", "--state", state, "--uvx", "/usr/bin/false"})
		case "cleanup":
			captureStdout(t, func() error { return cleanup([]string{"--state", state}) })
		case "cleanup while running":
			unlock, err := lockState(state)
			if err != nil {
				t.Fatal(err)
			}
			captureStdout(t, func() error { return cleanup([]string{"--state", state}) })
			unlock()
		}
		back := proxies["webproxy|Wi-Fi"] == corp
		if want := how != "cleanup while running"; back != want {
			t.Errorf("%s: put back %v, want %v: %+v", how, back, want, proxies)
		}
	}
}

// Settings saved and not put back yet are never saved over: the next point is
// refused. Settings already pointed at reqcove (by a run with other state)
// are not taken for the ones to put back.
func TestSystemProxyKeepsTheOriginal(t *testing.T) {
	state := t.TempDir()
	corp := webProxy{true, "proxy.corp", "3128"}
	proxies := map[string]webProxy{"webproxy|Wi-Fi": corp}
	fakeNetworksetup(t, proxies, "")
	if err := pointSystemProxy(state); err != nil {
		t.Fatal(err)
	}
	if err := pointSystemProxy(state); err == nil {
		t.Error("pointed again over saved settings")
	}
	restoreSystemProxy(state)
	if proxies["webproxy|Wi-Fi"] != corp {
		t.Errorf("the original is lost: %+v", proxies["webproxy|Wi-Fi"])
	}
	// Turned off with reqcove's address left in it (as an earlier run put an
	// empty proxy back): not pointed at reqcove, so not refused.
	left := t.TempDir()
	proxies["webproxy|Wi-Fi"] = webProxy{false, "127.0.0.1", "8082"}
	if err := pointSystemProxy(left); err != nil {
		t.Errorf("refused over a turned-off proxy: %v", err)
	}
	restoreSystemProxy(left)
	if proxies["webproxy|Wi-Fi"].Enabled {
		t.Errorf("put back on: %+v", proxies["webproxy|Wi-Fi"])
	}
	// Pointed at a reqcove already (another --state holds the original): refused, nothing saved.
	other := t.TempDir()
	proxies["webproxy|Wi-Fi"] = webProxy{true, "127.0.0.1", "8082"}
	if err := pointSystemProxy(other); err == nil || !strings.Contains(err.Error(), "another --state") {
		t.Errorf("pointed over another reqcove's: %v", err)
	}
	if _, err := os.Stat(savedProxyFile(other)); !os.IsNotExist(err) {
		t.Error("saved reqcove's own setting as the original")
	}
}

// A service gone since (a VPN's, a USB adapter's) is skipped when putting back;
// one that fails otherwise keeps the file, and the error says where it is.
func TestRestoreSkipsGoneServices(t *testing.T) {
	state := t.TempDir()
	proxies := map[string]webProxy{}
	fakeNetworksetup(t, proxies, "")
	os.WriteFile(savedProxyFile(state), []byte(`[{"service":"Gone VPN","web":{"enabled":true,"server":"p","port":"1"}},{"service":"Wi-Fi","web":{"enabled":true,"server":"proxy.corp","port":"3128"}}]`), 0o600)
	if err := restoreSystemProxy(state); err != nil {
		t.Fatal(err)
	}
	if proxies["webproxy|Wi-Fi"] != (webProxy{true, "proxy.corp", "3128"}) {
		t.Errorf("Wi-Fi: %+v", proxies["webproxy|Wi-Fi"])
	}
	if _, err := os.Stat(savedProxyFile(state)); !os.IsNotExist(err) {
		t.Error("the file stayed")
	}
	fakeNetworksetup(t, proxies, "-setwebproxy Wi-Fi")
	os.WriteFile(savedProxyFile(state), []byte(`[{"service":"Wi-Fi","web":{"enabled":true,"server":"proxy.corp","port":"3128"}}]`), 0o600)
	if err := restoreSystemProxy(state); err == nil || !strings.Contains(err.Error(), savedProxyFile(state)) {
		t.Errorf("a failure: %v", err)
	}
}

// withSystemProxy puts the settings back however what it wraps ends.
func TestWithSystemProxy(t *testing.T) {
	state := t.TempDir()
	corp := webProxy{true, "proxy.corp", "3128"}
	proxies := map[string]webProxy{"webproxy|Wi-Fi": corp}
	fakeNetworksetup(t, proxies, "")
	var during webProxy
	err := withSystemProxy(state, true, func() error { during = proxies["webproxy|Wi-Fi"]; return errors.New("port 8082 busy") })
	if err == nil || proxies["webproxy|Wi-Fi"] != corp {
		t.Errorf("after: %v %+v", err, proxies["webproxy|Wi-Fi"])
	}
	if want := runtime.GOOS == "darwin"; (during.Port == "8082") != want {
		t.Errorf("during, on %s: %+v", runtime.GOOS, during)
	}
}

// networksetup can print "** Error" and exit 0.
func TestNetworksetupError(t *testing.T) {
	if nsError("** Error: Unable to find item in network database.\n", nil) == nil || nsError("Enabled: No\n", nil) != nil {
		t.Error("nsError")
	}
}

// cleanup --delete-state keeps the state while it holds settings to put back.
func TestCleanupKeepsSavedProxy(t *testing.T) {
	state := t.TempDir()
	if unlock, err := openState(state); err != nil {
		t.Fatal(err)
	} else {
		unlock()
	}
	proxies := map[string]webProxy{}
	fakeNetworksetup(t, proxies, "-setwebproxystate") // putting back fails
	proxies["webproxy|Wi-Fi"] = webProxy{}
	os.WriteFile(savedProxyFile(state), []byte(`[{"service":"Wi-Fi","web":{"enabled":false}}]`), 0o600)
	r, w, _ := os.Pipe()
	oldOut := os.Stdout
	os.Stdout = w
	err := cleanup([]string{"--state", state, "--delete-state"})
	w.Close()
	os.Stdout = oldOut
	r.Close()
	if err == nil {
		t.Error("deleted the state holding settings to put back")
	}
	if _, err := os.Stat(savedProxyFile(state)); err != nil {
		t.Error("the saved settings are gone")
	}
}

// This Mac's trust in the CA: checked without a prompt (-l for a CA, -L -R
// offline), trusted for TLS only (-p ssl), and removed by fingerprint with
// its trust (-t -Z).
func TestMacTrust(t *testing.T) {
	var asked []string
	old := security
	defer func() { security = old }()
	security = func(args ...string) error { asked = args; return nil }
	if got := macTrusts("/s/ca.pem"); got != (runtime.GOOS == "darwin") {
		t.Errorf("trusted: %v on %s", got, runtime.GOOS)
	}
	if runtime.GOOS == "darwin" && strings.Join(asked, " ") != "verify-cert -c /s/ca.pem -l -p ssl -L -R offline -q" {
		t.Errorf("asked %q", asked)
	}
	security = func(...string) error { return errors.New("exit status 1") }
	if macTrusts("/s/ca.pem") {
		t.Error("untrusted taken for trusted")
	}
	if c := macTrustCommand("/s/ca.pem"); c != "security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db /s/ca.pem" {
		t.Errorf("trust: %s", c)
	}
	if c := macUntrustCommand("AB12"); c != "security delete-certificate -t -Z AB12 ~/Library/Keychains/login.keychain-db" {
		t.Errorf("untrust: %s", c)
	}
}

// cleanup tells how to stop this Mac trusting the CA, when it does.
func TestCleanupMacTrust(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	state := t.TempDir()
	if unlock, err := openState(state); err != nil {
		t.Fatal(err)
	} else {
		unlock()
	}
	os.MkdirAll(filepath.Join(state, "mitmproxy"), 0o700)
	os.WriteFile(filepath.Join(state, "mitmproxy", "mitmproxy-ca-cert.pem"), testCAPEM(t), 0o600)
	old := security
	defer func() { security = old }()
	for _, trusted := range []bool{true, false} {
		security = func(...string) error {
			if trusted {
				return nil
			}
			return errors.New("exit status 1")
		}
		out := captureStdout(t, func() error { return cleanup([]string{"--state", state}) })
		if got := strings.Contains(out, "security delete-certificate -t -Z "); got != trusted {
			t.Errorf("trusted %v: said %v:\n%s", trusted, got, out)
		}
	}
}

// testCAPEM is a CA certificate, as mitmproxy-ca-cert.pem holds it.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Reqcove CA (test)"}, NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// networksetup runs in a process group of its own, out of reach of the
// terminal's Ctrl-C while run puts the proxies back.
func TestNetworksetupOwnGroup(t *testing.T) {
	if c := nsCommand("-listallnetworkservices"); c.SysProcAttr == nil || !c.SysProcAttr.Setpgid {
		t.Error("networksetup shares the terminal's process group")
	}
}

// TestMacTrustCommandQuotes: a state directory with a space gives a command
// that still runs as printed.
func TestMacTrustCommandQuotes(t *testing.T) {
	got := macTrustCommand("/tmp/reqcove two/mitmproxy/mitmproxy-ca-cert.pem")
	if !strings.HasSuffix(got, " '/tmp/reqcove two/mitmproxy/mitmproxy-ca-cert.pem'") {
		t.Errorf("not quoted: %s", got)
	}
}
