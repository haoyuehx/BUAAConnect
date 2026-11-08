package netownership

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"inet.af/netaddr"
)

type recordedCommand struct {
	name string
	args []string
}

type fakeRunner struct {
	mu       sync.Mutex
	commands []recordedCommand
	respond  func(name string, args ...string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.commands = append(f.commands, recordedCommand{name: name, args: append([]string(nil), args...)})
	f.mu.Unlock()
	if f.respond != nil {
		return f.respond(name, args...)
	}
	return nil, nil
}

func (f *fakeRunner) recorded() []recordedCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCommand(nil), f.commands...)
}

func (f *fakeRunner) commandStrings() []string {
	recorded := f.recorded()
	result := make([]string, 0, len(recorded))
	for _, command := range recorded {
		result = append(result, strings.TrimSpace(command.name+" "+strings.Join(command.args, " ")))
	}
	return result
}

func TestMergeExtraRoutesAddsResourcesAndPrefixes(t *testing.T) {
	resources, prefixes, err := MergeExtraRoutes(nil, nil, []string{"10.1.2.0/24", "192.168.50.7"}, nil)
	if err != nil {
		t.Fatalf("MergeExtraRoutes() error = %v", err)
	}
	wantPrefixes := []string{"10.1.2.0/24", "192.168.50.7/32"}
	if !reflect.DeepEqual(prefixes, wantPrefixes) {
		t.Fatalf("prefixes = %#v, want %#v", prefixes, wantPrefixes)
	}
	if len(resources) != 2 {
		t.Fatalf("resources = %#v, want 2 resources", resources)
	}
	for i, resource := range resources {
		if !resource.IPMin.Equal(resources[i].IPMax) {
			t.Fatalf("resource %d IPMin != IPMax: %#v", i, resource)
		}
		if resource.PortMin != 1 || resource.PortMax != 65535 || resource.Protocol != "all" {
			t.Fatalf("resource %d = %#v, want all ports/all protocols", i, resource)
		}
	}
}

func TestMergeExtraRoutesSkipsServerAddresses(t *testing.T) {
	_, prefixes, err := MergeExtraRoutes(nil, nil,
		[]string{"10.0.0.0/8", "172.16.0.0/16"},
		[]net.IP{net.IPv4(10, 5, 6, 7), net.IPv4(192, 168, 1, 1)})
	if err != nil {
		t.Fatalf("MergeExtraRoutes() error = %v", err)
	}
	want := []string{"172.16.0.0/16"}
	if !reflect.DeepEqual(prefixes, want) {
		t.Fatalf("prefixes = %#v, want %#v", prefixes, want)
	}
}

func TestMergeExtraRoutesDeduplicatesAndValidates(t *testing.T) {
	_, prefixes, err := MergeExtraRoutes(nil, nil, []string{"10.2.0.0/16", "10.2.9.9/16"}, nil)
	if err != nil {
		t.Fatalf("MergeExtraRoutes() error = %v", err)
	}
	if len(prefixes) != 1 || prefixes[0] != "10.2.0.0/16" {
		t.Fatalf("prefixes = %#v, want one canonical prefix", prefixes)
	}

	original := []client.IPResource{{IPMin: net.IPv4(10, 0, 0, 1), IPMax: net.IPv4(10, 0, 0, 1), Protocol: "tcp"}}
	resources, prefixes, err := MergeExtraRoutes(original, nil, []string{"not-an-ip"}, nil)
	if err == nil {
		t.Fatal("MergeExtraRoutes() accepted an invalid route")
	}
	if !reflect.DeepEqual(resources, original) || prefixes != nil {
		t.Fatalf("invalid input returned partial result: resources=%#v prefixes=%#v", resources, prefixes)
	}
}

func TestMergeExtraRoutesExistingSetIsNotMutated(t *testing.T) {
	builder := netaddr.IPSetBuilder{}
	builder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/24"))
	staticSet, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	before := staticSet.Prefixes()

	resources, prefixes, err := MergeExtraRoutes(nil, staticSet, []string{"10.0.0.0/24", "10.9.0.0/16"}, nil)
	if err != nil {
		t.Fatalf("MergeExtraRoutes() error = %v", err)
	}
	if len(resources) != 2 || len(prefixes) != 2 {
		t.Fatalf("resources=%#v prefixes=%#v, want both extra routes", resources, prefixes)
	}
	if !reflect.DeepEqual(staticSet.Prefixes(), before) {
		t.Fatal("MergeExtraRoutes mutated the input IPSet")
	}

	mergedSet, err := AppendExtraRoutesToIPSet(staticSet, prefixes)
	if err != nil {
		t.Fatalf("AppendExtraRoutesToIPSet() error = %v", err)
	}
	if !mergedSet.Contains(netaddr.MustParseIP("10.9.1.1")) {
		t.Fatal("merged IPSet does not contain the extra route address")
	}
	if !mergedSet.Contains(netaddr.MustParseIP("10.0.0.9")) {
		t.Fatal("merged IPSet lost the original route")
	}
}

func TestRouteManagerTracksOnlyOwnedRoutes(t *testing.T) {
	runner := &fakeRunner{respond: func(_ string, args ...string) ([]byte, error) {
		if args[2] == "10.0.0.0/8" {
			return []byte("RTNETLINK answers: File exists"), errors.New("exit status 2")
		}
		return nil, nil
	}}
	manager := NewRouteManager("buaaconnect0", runner)

	if err := manager.AddRoute("10.0.0.0/8"); err != nil {
		t.Fatalf("AddRoute(existing) error = %v", err)
	}
	if err := manager.AddRoute("172.16.0.0/16"); err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}
	if got := manager.Routes(); !reflect.DeepEqual(got, []string{"172.16.0.0/16"}) {
		t.Fatalf("Routes() = %#v, want only the route we added", got)
	}

	if err := manager.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if got := manager.Routes(); len(got) != 0 {
		t.Fatalf("Routes() after rollback = %#v, want empty", got)
	}
	if err := manager.Rollback(); err != nil {
		t.Fatalf("second Rollback() error = %v", err)
	}

	deleteCommands := 0
	for _, command := range runner.commandStrings() {
		if strings.HasPrefix(command, "ip route del") {
			deleteCommands++
			if !strings.Contains(command, "172.16.0.0/16") {
				t.Fatalf("deleted an unowned route: %q", command)
			}
		}
	}
	if deleteCommands != 1 {
		t.Fatalf("ip route del commands = %d, want 1: %#v", deleteCommands, runner.commandStrings())
	}
}

func TestRouteManagerAddFailureDoesNotOwnRoute(t *testing.T) {
	runner := &fakeRunner{respond: func(string, ...string) ([]byte, error) {
		return []byte("RTNETLINK answers: Operation not permitted"), errors.New("exit status 2")
	}}
	manager := NewRouteManager("buaaconnect0", runner)
	if err := manager.AddRoute("10.1.0.0/16"); err == nil {
		t.Fatal("AddRoute() error = nil, want failure")
	}
	if got := manager.Routes(); len(got) != 0 {
		t.Fatalf("Routes() = %#v, want empty after failure", got)
	}
	if err := manager.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	for _, command := range runner.commandStrings() {
		if strings.HasPrefix(command, "ip route del") {
			t.Fatalf("rollback tried to delete a route it does not own: %q", command)
		}
	}
}

func TestRouteManagerRollbackRetriesFailedDeletes(t *testing.T) {
	failDelete := true
	runner := &fakeRunner{respond: func(_ string, args ...string) ([]byte, error) {
		if args[1] == "del" && failDelete {
			return nil, errors.New("temporary failure")
		}
		return nil, nil
	}}
	manager := NewRouteManager("buaaconnect0", runner)
	if err := manager.AddRoute("10.2.0.0/16"); err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}
	if err := manager.Rollback(); err == nil {
		t.Fatal("Rollback() error = nil, want failure")
	}
	if got := manager.Routes(); len(got) != 1 {
		t.Fatalf("Routes() after failed rollback = %#v, want the route retained", got)
	}
	failDelete = false
	if err := manager.Rollback(); err != nil {
		t.Fatalf("retry Rollback() error = %v", err)
	}
	if got := manager.Routes(); len(got) != 0 {
		t.Fatalf("Routes() after retry = %#v, want empty", got)
	}
}

func TestRouteManagerRollbackIgnoresAlreadyGoneRoutes(t *testing.T) {
	runner := &fakeRunner{respond: func(_ string, args ...string) ([]byte, error) {
		if args[1] == "del" {
			return []byte("RTNETLINK answers: No such process"), errors.New("exit status 2")
		}
		return nil, nil
	}}
	manager := NewRouteManager("buaaconnect0", runner)
	if err := manager.AddRoute("10.3.0.0/16"); err != nil {
		t.Fatalf("AddRoute() error = %v", err)
	}
	if err := manager.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if got := manager.Routes(); len(got) != 0 {
		t.Fatalf("Routes() = %#v, want empty", got)
	}
}

func TestDNSManagerOffNeverCallsResolvectl(t *testing.T) {
	runner := &fakeRunner{}
	manager := NewDNSManager("buaaconnect0", DNSModeOff, runner)
	if err := manager.Configure(net.IPv4(10, 0, 0, 2), []string{"~buaa.edu.cn"}); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if err := manager.Revert(); err != nil {
		t.Fatalf("Revert() error = %v", err)
	}
	if commands := runner.commandStrings(); len(commands) != 0 {
		t.Fatalf("commands = %#v, want none", commands)
	}
}

func TestDNSManagerAutoDegradesWhenResolvectlMissing(t *testing.T) {
	runner := &fakeRunner{respond: func(string, ...string) ([]byte, error) {
		return nil, errors.New("exec: \"resolvectl\": executable file not found in $PATH")
	}}
	manager := NewDNSManager("buaaconnect0", DNSModeAuto, runner)
	if err := manager.Configure(net.IPv4(10, 0, 0, 2), nil); err != nil {
		t.Fatalf("auto Configure() error = %v, want graceful degradation", err)
	}
	if manager.Configured() {
		t.Fatal("Configured() = true after failed auto configuration")
	}
}

func TestDNSManagerResolvectlModeSurfacesFailure(t *testing.T) {
	runner := &fakeRunner{respond: func(string, ...string) ([]byte, error) {
		return nil, fmt.Errorf("resolvectl failed")
	}}
	manager := NewDNSManager("buaaconnect0", DNSModeResolvectl, runner)
	if err := manager.Configure(net.IPv4(10, 0, 0, 2), nil); err == nil {
		t.Fatal("Configure() error = nil, want resolvectl failure")
	}
}

func TestDNSManagerConfiguresAndReverts(t *testing.T) {
	runner := &fakeRunner{}
	manager := NewDNSManager("buaaconnect0", DNSModeResolvectl, runner)
	domains := MergeDNSDomains(DefaultDNSDomains, []string{"*.example.com", "vpn.example.com", "~."})
	if err := manager.Configure(net.IPv4(10, 0, 0, 2), domains); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if !manager.Configured() {
		t.Fatal("Configured() = false after successful configuration")
	}
	commands := runner.commandStrings()
	want := []string{
		"resolvectl dns buaaconnect0 10.0.0.2",
		"resolvectl domain buaaconnect0 ~buaa.edu.cn ~example.com ~vpn.example.com ~.",
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}

	if err := manager.Revert(); err != nil {
		t.Fatalf("Revert() error = %v", err)
	}
	if err := manager.Revert(); err != nil {
		t.Fatalf("second Revert() error = %v", err)
	}
	reverts := 0
	for _, command := range runner.commandStrings() {
		if command == "resolvectl revert buaaconnect0" {
			reverts++
		}
	}
	if reverts != 1 {
		t.Fatalf("resolvectl revert commands = %d, want 1", reverts)
	}
}

func TestDNSManagerRejectsInvalidMode(t *testing.T) {
	manager := NewDNSManager("buaaconnect0", "systemd", &fakeRunner{})
	if err := manager.Configure(net.IPv4(10, 0, 0, 2), nil); err == nil {
		t.Fatal("Configure() error = nil, want invalid mode error")
	}
}

func TestNormalizeDNSDomain(t *testing.T) {
	tests := map[string]string{
		"":                    "",
		"buaa.edu.cn":         "~buaa.edu.cn",
		".example.com":        "~example.com",
		"*.example.com":       "~example.com",
		"~vpn.example.com":    "~vpn.example.com",
		"~.":                  "~.",
		".":                   "~.",
		"  buaa.edu.cn  ":     "~buaa.edu.cn",
		"*.deep.example.com.": "~deep.example.com",
	}
	for input, want := range tests {
		if got := NormalizeDNSDomain(input); got != want {
			t.Fatalf("NormalizeDNSDomain(%q) = %q, want %q", input, got, want)
		}
	}
}
