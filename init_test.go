package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/internal/runtime"
)

func TestSessionRefreshConfiguration(t *testing.T) {
	file := writeConfig(t, "session_refresh_interval = 900\n")
	for _, tt := range []struct {
		name string
		args []string
		env  []string
		want int
	}{
		{"default", []string{"--profile", "school"}, nil, 1800},
		{"file", []string{"--profile", "school", "--config", file}, nil, 900},
		{"environment", []string{"--profile", "school", "--config", file}, []string{"ZJU_CONNECT_SESSION_REFRESH_INTERVAL=600"}, 600},
		{"cli", []string{"--profile", "school", "--config", file, "-session-refresh-interval", "300"}, []string{"ZJU_CONNECT_SESSION_REFRESH_INTERVAL=600"}, 300},
		{"disabled", []string{"--profile", "school", "--config", file, "--session-refresh-interval=0"}, nil, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			options, _, err := loadStartupOptions(tt.args, func() []string { return tt.env })
			if err != nil {
				t.Fatal(err)
			}
			if got := options.Config.SessionRefreshInterval; got != tt.want {
				t.Fatalf("session refresh seconds = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigSourcePrecedence(t *testing.T) {
	configFile := writeConfig(t, `
protocol = "atrust"
server_address = "file.example.com"
server_port = 444
username = "file-user"
tun_mode = true
`)

	options, _, err := loadStartupOptions([]string{
		"--config", configFile,
		"--server", "cli.example.com",
		"--tun-mode=false",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_SERVER_ADDRESS=env.example.com",
			"ZJU_CONNECT_SERVER_PORT=555",
			"ZJU_CONNECT_USERNAME=env-user",
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := options.Config
	if cfg.ServerAddress != "cli.example.com" {
		t.Fatalf("ServerAddress = %q, want CLI value", cfg.ServerAddress)
	}
	if cfg.ServerPort != 555 {
		t.Fatalf("ServerPort = %d, want environment value", cfg.ServerPort)
	}
	if cfg.Username != "env-user" {
		t.Fatalf("Username = %q, want environment value", cfg.Username)
	}
	if cfg.Protocol != "atrust" {
		t.Fatalf("Protocol = %q, want TOML value", cfg.Protocol)
	}
	if cfg.TUNMode {
		t.Fatal("TUNMode = true, want explicit CLI false")
	}
}

func TestLegacySingleDashFlagsRemainSupported(t *testing.T) {
	options, _, err := loadStartupOptions([]string{
		"-protocol", "atrust",
		"-server=legacy.example.com",
		"-tun-mode",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.Protocol != "atrust" ||
		options.Config.ServerAddress != "legacy.example.com" ||
		!options.Config.TUNMode {
		t.Fatalf("legacy flags were not applied: %+v", options.Config)
	}
}

func TestLegacyArgumentNormalizationDoesNotRewriteValues(t *testing.T) {
	for _, passwordFlag := range []string{"-password", "--password"} {
		options, _, err := loadStartupOptions([]string{
			"--profile", "school",
			"-username", "user",
			passwordFlag, "-server",
		}, func() []string { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if options.Config.Password != "-server" {
			t.Fatalf("%s value = %q, want unchanged flag-like value", passwordFlag, options.Config.Password)
		}
	}
}

func TestUnchangedCLIValuesDoNotOverrideConfig(t *testing.T) {
	configFile := writeConfig(t, `
server_port = 8443
socks_bind = "127.0.0.1:2080"
`)

	options, _, err := loadStartupOptions([]string{"--profile", "school", "--config", configFile}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.ServerPort != 8443 {
		t.Fatalf("ServerPort = %d, want 8443", options.Config.ServerPort)
	}
	if options.Config.SocksBind != "127.0.0.1:2080" {
		t.Fatalf("SocksBind = %q, want TOML value", options.Config.SocksBind)
	}
}

func TestEnvironmentConfigPathAndAuthInfo(t *testing.T) {
	configFile := writeConfig(t, `
protocol = "atrust"
server_address = "vpn.example.com"
`)

	options, _, err := loadStartupOptions([]string{"--auth-info"}, func() []string {
		return []string{"ZJU_CONNECT_CONFIG=" + configFile}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.AuthInfo {
		t.Fatal("AuthInfo = false")
	}
	if options.Config.Protocol != "atrust" || options.Config.ServerAddress != "vpn.example.com" {
		t.Fatalf("config not loaded before auth-info: %+v", options.Config)
	}
}

func TestProtocolServerWorkaround(t *testing.T) {
	for _, tt := range []struct {
		name     string
		protocol string
		server   string
		want     string
		wantErr  bool
	}{
		{name: "empty server rejected", protocol: "atrust", wantErr: true},
		{name: "aTrust rewrites EasyConnect server", protocol: "atrust", server: "rvpn.zju.edu.cn", want: "vpn.zju.edu.cn"},
		{name: "EasyConnect rewrites aTrust server", protocol: "easyconnect", server: "vpn.zju.edu.cn", want: "rvpn.zju.edu.cn"},
		{name: "aTrust server remains unchanged", protocol: "atrust", server: "vpn.zju.edu.cn", want: "vpn.zju.edu.cn"},
		{name: "EasyConnect server remains unchanged", protocol: "easyconnect", server: "rvpn.zju.edu.cn", want: "rvpn.zju.edu.cn"},
		{name: "custom server remains unchanged", protocol: "atrust", server: "vpn.example.com", want: "vpn.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--protocol", tt.protocol, "--disable-zju-config=false"}
			if tt.server != "" {
				args = append(args, "--server", tt.server)
			}

			options, _, err := loadStartupOptions(args, func() []string { return nil })
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error for empty server address")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if options.Config.ServerAddress != tt.want {
				t.Fatalf("ServerAddress = %q, want %q", options.Config.ServerAddress, tt.want)
			}
		})
	}
}

func TestCollectionCLIReplacesConfig(t *testing.T) {
	configFile := writeConfig(t, `
port_forwarding = [
  { network_type = "tcp", bind_address = "127.0.0.1:1", remote_address = "10.0.0.1:1" }
]
custom_proxy_domain = ["file.example.com"]
`)

	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--config", configFile,
		"--tcp-port-forwarding", "127.0.0.1:2-10.0.0.2:2",
		"--udp-port-forwarding", "127.0.0.1:3-10.0.0.3:3",
		"--custom-proxy-domain", "cli.example.com",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Config.PortForwardingList) != 2 {
		t.Fatalf("PortForwardingList = %+v", options.Config.PortForwardingList)
	}
	if got := options.Config.CustomProxyDomain; len(got) != 1 || got[0] != "cli.example.com" {
		t.Fatalf("CustomProxyDomain = %v", got)
	}
}

func TestUnknownConfigurationKeyIsRejected(t *testing.T) {
	configFile := writeConfig(t, "server_adress = \"typo.example.com\"\n")
	if _, _, err := loadStartupOptions([]string{"--profile", "school", "--config", configFile}, func() []string { return nil }); err == nil {
		t.Fatal("unknown TOML key was accepted")
	}

	if _, _, err := loadStartupOptions(nil, func() []string {
		return []string{"ZJU_CONNECT_SERVER_ADRESS=typo.example.com"}
	}); err == nil {
		t.Fatal("unknown environment key was accepted")
	}
}

func TestLegacyRemoteDNSNamesRemainSupported(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		args    []string
		environ []string
		wantDNS string
	}{
		{
			name:    "TOML",
			config:  "disable_zju_dns = true\nzju_dns_server = \"192.0.2.1\"\n",
			wantDNS: "192.0.2.1",
		},
		{
			name: "environment",
			environ: []string{
				"ZJU_CONNECT_DISABLE_ZJU_DNS=true",
				"ZJU_CONNECT_ZJU_DNS_SERVER=192.0.2.2",
			},
			wantDNS: "192.0.2.2",
		},
		{
			name: "command line",
			args: []string{
				"--profile", "school",
				"--disable-zju-dns",
				"--zju-dns-server", "192.0.2.3",
			},
			wantDNS: "192.0.2.3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--profile", "school"}, test.args...)
			if test.config != "" {
				args = append([]string{"--config", writeConfig(t, test.config)}, args...)
			}
			options, _, err := loadStartupOptions(args, func() []string { return test.environ })
			if err != nil {
				t.Fatal(err)
			}
			if !options.Config.DisableRemoteDNS {
				t.Fatal("DisableRemoteDNS = false, want true")
			}
			if options.Config.RemoteDNSServer != test.wantDNS {
				t.Fatalf("RemoteDNSServer = %q, want %q", options.Config.RemoteDNSServer, test.wantDNS)
			}
		})
	}
}

func TestCanonicalRemoteDNSConfigNames(t *testing.T) {
	configFile := writeConfig(t, `
disable_remote_dns = true
remote_dns_server = "192.0.2.4"
`)

	options, _, err := loadStartupOptions([]string{"--profile", "school", "--config", configFile}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !options.Config.DisableRemoteDNS || options.Config.RemoteDNSServer != "192.0.2.4" {
		t.Fatalf("canonical remote DNS configuration was not applied: %+v", options.Config)
	}
}

func TestRemoteDNSAliasesPreserveSourcePrecedence(t *testing.T) {
	configFile := writeConfig(t, `
disable_zju_dns = true
zju_dns_server = "192.0.2.1"
`)

	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--config", configFile,
		"--disable-zju-dns=false",
		"--remote-dns-server", "192.0.2.3",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_DISABLE_REMOTE_DNS=true",
			"ZJU_CONNECT_ZJU_DNS_SERVER=192.0.2.2",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.DisableRemoteDNS {
		t.Fatal("DisableRemoteDNS = true, want explicit CLI false")
	}
	if options.Config.RemoteDNSServer != "192.0.2.3" {
		t.Fatalf("RemoteDNSServer = %q, want CLI value", options.Config.RemoteDNSServer)
	}
}

func TestEnvironmentCollectionsUseCLISyntax(t *testing.T) {
	options, _, err := loadStartupOptions([]string{"--profile", "school"}, func() []string {
		return []string{
			"ZJU_CONNECT_TCP_PORT_FORWARDING=127.0.0.1:2-10.0.0.2:2",
			"ZJU_CONNECT_UDP_PORT_FORWARDING=127.0.0.1:3-10.0.0.3:3",
			"ZJU_CONNECT_CUSTOM_PROXY_DOMAIN=one.example.com,two.example.com",
			"ZJU_CONNECT_CUSTOM_DNS=host.example.com:192.0.2.1",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Config.CustomProxyDomain) != 2 {
		t.Fatalf("CustomProxyDomain = %v", options.Config.CustomProxyDomain)
	}
	if len(options.Config.PortForwardingList) != 2 {
		t.Fatalf("PortForwardingList = %+v", options.Config.PortForwardingList)
	}
	if len(options.Config.CustomDNSList) != 1 || options.Config.CustomDNSList[0].IP != "192.0.2.1" {
		t.Fatalf("CustomDNSList = %+v", options.Config.CustomDNSList)
	}
}

func TestCLICollectionsOverrideEnvironmentCollections(t *testing.T) {
	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--tcp-port-forwarding", "127.0.0.1:4-10.0.0.4:4",
		"--custom-proxy-domain", "cli.example.com",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_TCP_PORT_FORWARDING=127.0.0.1:2-10.0.0.2:2",
			"ZJU_CONNECT_UDP_PORT_FORWARDING=127.0.0.1:3-10.0.0.3:3",
			"ZJU_CONNECT_CUSTOM_PROXY_DOMAIN=env.example.com",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := options.Config.PortForwardingList; len(got) != 1 || got[0].RemoteAddress != "10.0.0.4:4" {
		t.Fatalf("PortForwardingList = %+v", got)
	}
	if got := options.Config.CustomProxyDomain; len(got) != 1 || got[0] != "cli.example.com" {
		t.Fatalf("CustomProxyDomain = %v", got)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSubcommands(t *testing.T) {
	for _, tt := range []struct {
		args string
		want string
	}{
		{"connect --server vpn.buaa.edu.cn", "connect"},
		{"status", "status"},
		{"disconnect", "disconnect"},
		{"doctor", "doctor"},
		{"version", "version"},
		{"--server vpn.buaa.edu.cn", "connect"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			options, _, err := loadStartupOptions(strings.Fields(tt.args), func() []string { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if options.Subcommand != tt.want {
				t.Fatalf("Subcommand = %q, want %q", options.Subcommand, tt.want)
			}
		})
	}
}

func TestUnknownSubcommandRejected(t *testing.T) {
	if _, _, err := loadStartupOptions([]string{"foo"}, func() []string { return nil }); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestProfileDefaults(t *testing.T) {
	for _, profile := range []string{"school", "act"} {
		t.Run(profile, func(t *testing.T) {
			args := []string{"--profile", profile}
			options, _, err := loadStartupOptions(args, func() []string { return nil })
			if err != nil {
				t.Fatal(err)
			}
			cfg := options.Config
			if cfg.Profile != profile || !cfg.TUNMode || !cfg.AddRoute {
				t.Fatalf("unexpected profile config: %+v", cfg)
			}
			if profile == "school" && cfg.ServerAddress != "vpn.buaa.edu.cn" {
				t.Fatalf("school server = %q", cfg.ServerAddress)
			}
			if profile == "act" && cfg.ServerAddress != "vpn.act.buaa.edu.cn" {
				t.Fatalf("act server = %q", cfg.ServerAddress)
			}
		})
	}
}

func TestProfileEnvOverridesZJUEnv(t *testing.T) {
	options, _, err := loadStartupOptions(nil, func() []string {
		return []string{
			"ZJU_CONNECT_PROFILE=act",
			"BUAA_CONNECT_PROFILE=school",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.Profile != "school" || options.Config.ServerAddress != "vpn.buaa.edu.cn" {
		t.Fatalf("BUAA env did not win: %+v", options.Config)
	}
}

func TestBuaaEnvPrecedence(t *testing.T) {
	configFile := writeConfig(t, `
server_address = "file.example.com"
username = "file-user"
`)
	oldReader := stdinPasswordReader
	stdinPasswordReader = func() (string, error) { return "env-pass", nil }
	defer func() { stdinPasswordReader = oldReader }()

	options, _, err := loadStartupOptions([]string{
		"--config", configFile,
		"--server", "cli.example.com",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_SERVER_ADDRESS=env-zju.example.com",
			"BUAA_CONNECT_SERVER_ADDRESS=env-buaa.example.com",
			"BUAA_CONNECT_USERNAME=env-buaa-user",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.ServerAddress != "cli.example.com" {
		t.Fatalf("CLI did not win: %q", options.Config.ServerAddress)
	}
	if options.Config.Username != "env-buaa-user" {
		t.Fatalf("BUAA env did not win: %q", options.Config.Username)
	}
}

func TestConfigOverridesProfileDefaults(t *testing.T) {
	configFile := writeConfig(t, `
server_address = "file.example.com"
`)
	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--config", configFile,
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.ServerAddress != "file.example.com" {
		t.Fatalf("config did not override profile default: %q", options.Config.ServerAddress)
	}
	// CLI --profile still wins over a config-file profile value.
	if options.Config.Profile != "school" {
		t.Fatalf("Profile = %q, want school", options.Config.Profile)
	}
}

func TestExtraRoutes(t *testing.T) {
	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--extra-routes", "10.212.0.5,10.212.1.0/24",
		"--extra-route", "10.212.2.6",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.212.0.5/32", "10.212.1.0/24", "10.212.2.6/32"}
	if len(options.Config.ExtraRoutes) != len(want) {
		t.Fatalf("ExtraRoutes = %v", options.Config.ExtraRoutes)
	}
	for i, v := range want {
		if options.Config.ExtraRoutes[i] != v {
			t.Fatalf("ExtraRoutes[%d] = %q, want %q", i, options.Config.ExtraRoutes[i], v)
		}
	}
}

func TestExtraRoutesEnv(t *testing.T) {
	options, _, err := loadStartupOptions([]string{"--profile", "school"}, func() []string {
		return []string{"BUAA_CONNECT_EXTRA_ROUTES=10.0.0.0/8"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Config.ExtraRoutes) != 1 || options.Config.ExtraRoutes[0] != "10.0.0.0/8" {
		t.Fatalf("ExtraRoutes = %v", options.Config.ExtraRoutes)
	}
}

func TestInvalidExtraRoute(t *testing.T) {
	if _, _, err := loadStartupOptions([]string{"--extra-routes", "invalid"}, func() []string { return nil }); err == nil {
		t.Fatal("expected error for invalid extra route")
	}
}

func TestSystemDNSValidation(t *testing.T) {
	if _, _, err := loadStartupOptions([]string{"--system-dns", "foo"}, func() []string { return nil }); err == nil {
		t.Fatal("expected error for invalid system-dns")
	}
	options, _, err := loadStartupOptions([]string{"--profile", "school", "--system-dns", "off"}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.SystemDNS != "off" {
		t.Fatalf("SystemDNS = %q", options.Config.SystemDNS)
	}
}

func TestMissingServerAddressRequiresProfileOrConfig(t *testing.T) {
	if _, _, err := loadStartupOptions([]string{
		"--username", "user",
		"--password", "pass",
	}, func() []string { return nil }); err == nil {
		t.Fatal("expected error when server address is missing")
	}
}

func TestPasswordPrompt(t *testing.T) {
	oldReader := stdinPasswordReader
	stdinPasswordReader = func() (string, error) { return "prompted-pass", nil }
	defer func() { stdinPasswordReader = oldReader }()

	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--username", "user",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.Password != "prompted-pass" {
		t.Fatalf("Password = %q, want prompted value", options.Config.Password)
	}
}

func TestVersionSubcommand(t *testing.T) {
	options, _, err := loadStartupOptions([]string{"version"}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Subcommand != "version" || !options.ShowVersion {
		t.Fatalf("version subcommand not recognized: %+v", options)
	}
}

func TestFilterSecretArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "long form with separate value",
			in:   []string{"connect", "--profile", "school", "--username", "user", "--password", "secret", "--server", "vpn.buaa.edu.cn"},
			want: []string{"connect", "--profile", "school", "--username", "user", "--server", "vpn.buaa.edu.cn"},
		},
		{
			name: "single dash with equals",
			in:   []string{"-password=secret", "--server", "vpn.buaa.edu.cn"},
			want: []string{"--server", "vpn.buaa.edu.cn"},
		},
		{
			name: "all secret flags and forms",
			in: []string{
				"connect",
				"--password", "p",
				"-cert-password=cp",
				"--totp-secret=ts",
				"-socks-passwd", "sp",
				"--sign-key", "sk",
				"-oauth2-code=oc",
				"--cas-ticket", "ct",
				"-sid", "s",
				"--device-id", "d",
				"-twf-id=t",
				"--server", "vpn.buaa.edu.cn",
			},
			want: []string{"connect", "--server", "vpn.buaa.edu.cn"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filterSecretArgs(tc.in)
			if len(out) != len(tc.want) {
				t.Fatalf("filterSecretArgs = %v, want %v", out, tc.want)
			}
			for i := range tc.want {
				if out[i] != tc.want[i] {
					t.Fatalf("filterSecretArgs = %v, want %v", out, tc.want)
				}
			}
			for _, v := range out {
				if strings.Contains(v, "secret") || v == "p" || v == "cp" || v == "ts" || v == "sp" || v == "sk" || v == "oc" || v == "ct" || v == "s" || v == "d" || v == "t" {
					// The remaining value "vpn.buaa.edu.cn" is safe; all short
					// secrets above must have been removed.
					if v == "vpn.buaa.edu.cn" {
						continue
					}
					t.Fatalf("secret value leaked into filtered args: %q", v)
				}
			}
		})
	}
}

func TestStateFileDoesNotContainSecrets(t *testing.T) {
	options, _, err := loadStartupOptions([]string{
		"--profile", "school",
		"--username", "user",
		"--password", "super-secret-password",
		"--totp-secret", "shhh-totp",
		"--cert-password", "cert-pass",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: secrets were loaded into the in-memory config.
	if options.Config.Password != "super-secret-password" {
		t.Fatalf("Password not loaded: %q", options.Config.Password)
	}

	stateDir := t.TempDir()
	mgr, err := runtime.NewManager(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Acquire(options.Config.Profile, options.Config.Protocol, options.Config.ServerAddress); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(mgr.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(data))
	for _, secret := range []string{"super-secret-password", "shhh-totp", "cert-pass"} {
		if strings.Contains(lower, strings.ToLower(secret)) {
			t.Fatalf("state file contains secret %q: %s", secret, string(data))
		}
	}
	if strings.Contains(lower, "argv") || strings.Contains(lower, "username") {
		// Full command line arguments must not be persisted.
		t.Fatalf("state file appears to contain command-line arguments: %s", string(data))
	}
}

func TestDaemonFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-d", "--profile", "school"},
		{"--daemon", "--profile", "school"},
		{"--profile", "school", "--daemon=true"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			options, _, err := loadStartupOptions(args, func() []string { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if !options.Config.Daemon {
				t.Fatalf("Daemon = false for args %v", args)
			}
		})
	}
}

func TestDaemonChildDisablesDaemon(t *testing.T) {
	t.Setenv("BUAA_CONNECT_DAEMON_CHILD", "1")
	options, _, err := loadStartupOptions([]string{
		"--daemon", "--profile", "school",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.Daemon {
		t.Fatal("Daemon = true in daemon child; this would cause infinite recursion")
	}
}

func TestProfileFromConfig(t *testing.T) {
	configFile := writeConfig(t, `profile = "act"
`)
	options, _, err := loadStartupOptions([]string{"--config", configFile}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	cfg := options.Config
	if cfg.Profile != "act" {
		t.Fatalf("Profile = %q, want act", cfg.Profile)
	}
	if cfg.ServerAddress != "vpn.act.buaa.edu.cn" {
		t.Fatalf("ServerAddress = %q, want vpn.act.buaa.edu.cn", cfg.ServerAddress)
	}
	if cfg.ServerPort != 8443 {
		t.Fatalf("ServerPort = %d, want 8443", cfg.ServerPort)
	}
	if !cfg.TUNMode {
		t.Fatal("TUNMode = false, want true from act profile defaults")
	}
}

func TestProfileFromConfigNormalized(t *testing.T) {
	configFile := writeConfig(t, `profile = "  ACT "
`)
	options, _, err := loadStartupOptions([]string{"--config", configFile}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.Profile != "act" {
		t.Fatalf("Profile = %q, want normalized act", options.Config.Profile)
	}
}
