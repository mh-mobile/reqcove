package main

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// fakeNetworksetup keeps proxies per service and answers like networksetup.
func fakeNetworksetup(t *testing.T, proxies map[string]webProxy, failSet string) *[]string {
	t.Helper()
	var calls []string
	old := networksetup
	t.Cleanup(func() { networksetup = old })
	networksetup = func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		switch cmd := args[0]; {
		case cmd == "-listallnetworkservices":
			return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB LAN\n*Bluetooth PAN\n", nil
		case strings.HasPrefix(cmd, "-get"):
			p := proxies[strings.TrimPrefix(cmd, "-get")+"|"+args[1]]
			on := "No"
			if p.Enabled {
				on = "Yes"
			}
			return "Enabled: " + on + "\nServer: " + p.Server + "\nPort: " + p.Port + "\nAuthenticated Proxy Enabled: 0\n", nil
		case failSet != "" && strings.Contains(strings.Join(args, " "), failSet):
			return "", errors.New("exit status 1")
		case strings.HasSuffix(cmd, "state"):
			proxies[strings.TrimSuffix(strings.TrimPrefix(cmd, "-set"), "state")+"|"+args[1]] = webProxy{}
		default:
			proxies[strings.TrimPrefix(cmd, "-set")+"|"+args[1]] = webProxy{true, args[2], args[3]}
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
	proxies := map[string]webProxy{"webproxy|Wi-Fi": corp, "securewebproxy|Wi-Fi": corp}
	calls := fakeNetworksetup(t, proxies, "")
	if err := pointSystemProxy(state); err != nil {
		t.Fatal(err)
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
	if proxies["webproxy|Wi-Fi"] != corp || proxies["securewebproxy|Wi-Fi"] != corp || proxies["webproxy|USB LAN"].Enabled || proxies["securewebproxy|USB LAN"].Enabled {
		t.Errorf("not put back: %+v", proxies)
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
			run(context.Background(), []string{"--local-proxy", "--allow-hosts", "api.example.com", "--state", state, "--uvx", "/usr/bin/false"})
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
