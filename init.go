package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/internal/doctor"
	"github.com/mythologyli/zju-connect/internal/runtime"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

const (
	envPrefix         = "ZJU_CONNECT_"
	buaaEnvPrefix     = "BUAA_CONNECT_"
	daemonChildEnvVar = "BUAA_CONNECT_DAEMON_CHILD"
)

var (
	zjuConnectVersion = "dev"
	CommitID          string
	domainPattern     = regexp.MustCompile(`^[a-zA-Z\d-]+(\.[a-zA-Z\d-]+)*\.[a-zA-Z]{2,}$`)
)

// stdinPasswordReader is swapped in tests to avoid terminal interaction.
var stdinPasswordReader = defaultReadPassword

// netDialTimeout is swapped in tests.
var netDialTimeout = net.DialTimeout

type startupOptions struct {
	Subcommand    string
	Config        configs.Config
	ShowVersion   bool
	AuthInfo      bool
	TrustDevice   bool
	UntrustDevice bool
	ProbeTarget   string
}

type collectionKey string

const (
	collectionTCPPortForwarding collectionKey = "tcp_port_forwarding"
	collectionUDPPortForwarding collectionKey = "udp_port_forwarding"
	collectionCustomDNS         collectionKey = "custom_dns"
	collectionProxyDomain       collectionKey = "custom_proxy_domain"
)

type collectionSpec struct {
	Key      collectionKey
	FlagName string
	EnvName  string
	Help     string
}

var collectionSpecs = []collectionSpec{
	{collectionTCPPortForwarding, "tcp-port-forwarding", "TCP_PORT_FORWARDING", "TCP port forwarding"},
	{collectionUDPPortForwarding, "udp-port-forwarding", "UDP_PORT_FORWARDING", "UDP port forwarding"},
	{collectionCustomDNS, "custom-dns", "CUSTOM_DNS", "Custom DNS lookup entries"},
	{collectionProxyDomain, "custom-proxy-domain", "CUSTOM_PROXY_DOMAIN", "Domains which force use of the RVPN proxy"},
}

type configAlias struct {
	LegacyKey     string
	CanonicalKey  string
	LegacyFlag    string
	CanonicalFlag string
}

var configAliases = []configAlias{
	{"disable_zju_dns", "disable_remote_dns", "disable-zju-dns", "disable-remote-dns"},
	{"zju_dns_server", "remote_dns_server", "zju-dns-server", "remote-dns-server"},
}

func zjuConnectVersionString() string {
	if CommitID != "" {
		return zjuConnectVersion + "-" + CommitID
	}
	return zjuConnectVersion
}

func newFlagSet(defaults configs.Config) *pflag.FlagSet {
	flags := pflag.NewFlagSet("buaaconnect", pflag.ContinueOnError)
	flags.String("profile", "", `Profile ("school" or "act")`)
	flags.String("protocol", defaults.Protocol, "Protocol (easyconnect, atrust)")
	flags.String("server", defaults.ServerAddress, "EasyConnect/aTrust server address")
	flags.Int("port", defaults.ServerPort, "EasyConnect/aTrust port address")
	flags.String("username", defaults.Username, "Your username")
	flags.String("password", defaults.Password, "Your password")
	flags.String("totp-secret", defaults.TOTPSecret, "TOTP secret")
	flags.String("cert-file", defaults.CertFile, "Client certificate p12 file path for certificate login")
	flags.String("cert-password", defaults.CertPassword, "Client certificate password")
	flags.Bool("disable-server-config", defaults.DisableServerConfig, "Don't parse server config")
	flags.Bool("skip-domain-resource", defaults.SkipDomainResource, "Don't use server domain resource to decide whether to use RVPN")
	flags.Bool("disable-zju-config", defaults.DisableZJUConfig, "Don't use ZJU config (for easyconnect protocol only)")
	flags.Bool("disable-remote-dns", defaults.DisableRemoteDNS, "Use local DNS instead of remote DNS")
	flags.Bool("disable-zju-dns", defaults.DisableRemoteDNS, "Use local DNS instead of remote DNS")
	_ = flags.MarkDeprecated("disable-zju-dns", "use --disable-remote-dns instead")
	flags.Bool("disable-multi-line", defaults.DisableMultiLine, "Disable multi line auto select")
	flags.Bool("proxy-all", defaults.ProxyAll, "Proxy all traffic (only for debug usage)")
	flags.String("socks-bind", defaults.SocksBind, "The address SOCKS5 server listens on")
	flags.String("socks-user", defaults.SocksUser, "SOCKS5 username")
	flags.String("socks-passwd", defaults.SocksPasswd, "SOCKS5 password")
	flags.String("http-bind", defaults.HTTPBind, "The address HTTP server listens on")
	flags.String("shadowsocks-url", defaults.ShadowsocksURL, "The address Shadowsocks server listens on")
	flags.String("dial-direct-proxy", defaults.DialDirectProxy, "Dial with proxy when a connection doesn't match RVPN rules")
	flags.Bool("tcp-tunnel-mode", defaults.TCPTunnelMode, "Use TCP tunnel only and disable L3 tunnel")
	flags.Bool("tun-mode", defaults.TUNMode, "Enable TUN mode (experimental)")
	flags.String("tun-name", defaults.TunName, "TUN interface name")
	flags.Bool("add-route", defaults.AddRoute, "Add route from rules for TUN interface")
	flags.String("extra-routes", "", "Comma-separated extra IPv4 routes (CIDR or IP)")
	flags.String("extra-route", "", "Alias for --extra-routes")
	_ = flags.MarkHidden("extra-route")
	flags.String("system-dns", defaults.SystemDNS, `System DNS mode ("auto", "resolvectl", "off")`)
	flags.Uint64("dns-ttl", defaults.DNSTTL, "DNS record time to live in seconds")
	flags.Bool("debug-dump", defaults.DebugDump, "Enable traffic debug dump")
	flags.String("debug-pcap-file", defaults.DebugPCAPFile, "Save reconstructed VPN traffic to a PCAP file")
	flags.String("debug-tls-log-file", defaults.DebugTLSLogFile, "Save TLS session secrets in NSS key log format")
	flags.Bool("disable-keep-alive", defaults.DisableKeepAlive, "Disable keep alive")
	flags.String("keep-alive-url", defaults.KeepAliveURL, "Keep alive URL")
	flags.String("remote-dns-server", defaults.RemoteDNSServer, "Remote DNS server address")
	flags.String("zju-dns-server", defaults.RemoteDNSServer, "Remote DNS server address")
	_ = flags.MarkDeprecated("zju-dns-server", "use --remote-dns-server instead")
	flags.String("secondary-dns-server", defaults.SecondaryDNSServer, "Secondary DNS server address")
	flags.String("dns-server-bind", defaults.DNSServerBind, "The address DNS server listens on")
	flags.String("local-dns-server", defaults.LocalDNSServer, "DNS server used to resolve the VPN server hostname")
	flags.Bool("dns-hijack", defaults.DNSHijack, "Hijack DNS queries to BUAAConnect")
	flags.Bool("fake-ip", defaults.FakeIP, "Enable Fake IP for DNS hijack")
	flags.String("graph-code-file", defaults.GraphCodeFile, "Graph Check Code File")
	flags.String("bind-interface", defaults.BindInterface, "Bind VPN underlay connections to this network interface")
	flags.Bool("auto-detect-interface", defaults.AutoDetectInterface, "Automatically detect and bind the VPN underlay interface")
	flags.String("twf-id", defaults.TwfID, "Login using captured twfID")
	flags.String("auth-type", defaults.AuthType, "aTrust authentication type")
	flags.String("phone", defaults.Phone, "Phone number with country code for aTrust SMS login")
	flags.String("login-domain", defaults.LoginDomain, "aTrust login domain")
	flags.String("client-data-file", defaults.ClientDataFile, "aTrust Client Data File")
	flags.String("cas-ticket", defaults.CasTicket, "aTrust CAS Ticket")
	flags.String("oauth2-code", defaults.OAuth2Code, "aTrust OAuth2 code")
	flags.String("sid", defaults.SID, "aTrust SID")
	flags.String("device-id", defaults.DeviceID, "aTrust Device ID")
	flags.String("sign-key", defaults.SignKey, "aTrust Sign Key")
	flags.String("resource-file", defaults.ResourceFile, "aTrust Resource File")
	flags.Int("update-best-nodes-interval", defaults.UpdateBestNodesInterval, "Interval to update best nodes in seconds")
	flags.Int("session-refresh-interval", defaults.SessionRefreshInterval, "aTrust session refresh interval in seconds (0 disables)")

	// Lifecycle flags.
	flags.BoolP("daemon", "d", defaults.Daemon, "Run in the background after reading credentials")
	flags.String("state-dir", defaults.StateDir, "Directory for runtime state and logs")
	flags.Int("max-reconnect", defaults.MaxReconnect, "Maximum reconnection attempts")
	flags.Int("reconnect-delay", defaults.ReconnectDelay, "Seconds between reconnection attempts")
	flags.String("probe", "", "Target host:port to probe (used by status and doctor)")

	for _, spec := range collectionSpecs {
		flags.String(spec.FlagName, "", spec.Help)
	}

	flags.String("config", "", "Config file (can also be set with BUAA_CONNECT_CONFIG or ZJU_CONNECT_CONFIG)")
	flags.Bool("version", false, "Show version")
	flags.Bool("auth-info", false, "Fetch aTrust authentication information, but do not login")
	flags.Bool("trust-device", false, "Trust the current device for aTrust, but do not connect")
	flags.Bool("untrust-device", false, "Untrust the current device for aTrust, but do not connect")
	return flags
}

func loadStartupOptions(args []string, environ func() []string) (startupOptions, *pflag.FlagSet, error) {
	envValues := environ()

	// Determine profile before parsing so that profile defaults become the base
	// template. Priority: CLI flag > BUAA env > ZJU env.
	profile := highestPriorityProfile(args, envValues)

	// Determine the config file path early so that a profile declared only in
	// the config file can still be used as the base template.
	configFile := ""
	if path, ok := lookupEnvironment(envValues, buaaEnvPrefix+"CONFIG"); ok {
		configFile = path
	} else if path, ok := lookupEnvironment(envValues, envPrefix+"CONFIG"); ok {
		configFile = path
	}
	if c, ok := parseFlagValue(args, "config"); ok && c != "" {
		configFile = c
	}

	if profile == "" && configFile != "" {
		if p, err := peekProfileFromConfig(configFile); err == nil && p != "" {
			profile = p
		}
	}

	defaults := configs.Default()
	if profile != "" {
		profileDefaults, err := configs.ProfileDefaults(profile)
		if err != nil {
			return startupOptions{}, nil, err
		}
		defaults = profileDefaults
	}

	flags := newFlagSet(defaults)
	if err := flags.Parse(normalizeLegacyArgs(flags, args)); err != nil {
		return startupOptions{}, flags, err
	}

	// Detect subcommand from remaining positional arguments. Default is connect.
	subcommand := "connect"
	positional := flags.Args()
	if len(positional) > 0 {
		switch positional[0] {
		case "connect", "status", "disconnect", "doctor", "version":
			subcommand = positional[0]
		default:
			return startupOptions{}, flags, fmt.Errorf("unknown subcommand %q", positional[0])
		}
	}

	showVersion, _ := flags.GetBool("version")
	authInfo, _ := flags.GetBool("auth-info")
	trustDevice, _ := flags.GetBool("trust-device")
	untrustDevice, _ := flags.GetBool("untrust-device")
	probeTarget, _ := flags.GetString("probe")
	if subcommand == "version" {
		showVersion = true
	}

	options := startupOptions{
		Subcommand:    subcommand,
		ShowVersion:   showVersion,
		AuthInfo:      authInfo,
		TrustDevice:   trustDevice,
		UntrustDevice: untrustDevice,
		ProbeTarget:   probeTarget,
	}
	if options.ShowVersion {
		return options, flags, nil
	}

	// Command-line --config wins over the environment variable.
	if flags.Lookup("config").Changed {
		configFile, _ = flags.GetString("config")
	}

	k := koanf.New(".")
	if err := k.Load(structs.Provider(defaults, "koanf"), nil); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load config defaults: %w", err)
	}

	allowedKeys := make(map[string]struct{}, len(k.Keys()))
	for _, key := range k.Keys() {
		allowedKeys[key] = struct{}{}
	}

	if configFile != "" {
		if err := k.Load(file.Provider(configFile), toml.Parser()); err != nil {
			return startupOptions{}, flags, fmt.Errorf("parse config %q: %w", configFile, err)
		}
		if err := normalizeConfigAliases(k); err != nil {
			return startupOptions{}, flags, fmt.Errorf("parse config %q: %w", configFile, err)
		}
		if err := rejectUnknownKeys(k, allowedKeys); err != nil {
			return startupOptions{}, flags, fmt.Errorf("parse config %q: %w", configFile, err)
		}
	}

	// Environment: ZJU first, then BUAA overrides.
	if err := loadEnvPrefix(k, envValues, envPrefix, allowedKeys); err != nil {
		return startupOptions{}, flags, err
	}
	if err := loadEnvPrefix(k, envValues, buaaEnvPrefix, allowedKeys); err != nil {
		return startupOptions{}, flags, err
	}
	if err := applyCollectionValues(k, collectionValuesFromEnvironment(envValues)); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load environment: %w", err)
	}

	cliProvider := posflag.ProviderWithFlag(flags, ".", k, func(flag *pflag.Flag) (string, any) {
		key, ok := configKeyForFlag(flag.Name)
		if !ok {
			return "", nil
		}
		return key, posflag.FlagVal(flags, flag)
	})
	if err := k.Load(cliProvider, nil); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load command line: %w", err)
	}
	if err := applyCollectionValues(k, collectionValuesFromFlags(flags)); err != nil {
		return startupOptions{}, flags, err
	}

	var cfg configs.Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return startupOptions{}, flags, fmt.Errorf("decode merged configuration: %w", err)
	}

	// Apply explicit extra-route alias.
	if flags.Lookup("extra-route").Changed {
		routeFlag, _ := flags.GetString("extra-route")
		cfg.ExtraRoutes = append(cfg.ExtraRoutes, splitExtraRoutes(routeFlag)...)
	}
	if err := normalizeExtraRoutes(&cfg); err != nil {
		return startupOptions{}, flags, err
	}

	// The ZJU server workaround is intentionally disabled by default.
	// Apply it only when the user explicitly opts in.
	if !cfg.DisableZJUConfig {
		zjuServerWorkaround(&cfg)
	}

	if err := validateConfig(cfg); err != nil {
		return startupOptions{}, flags, err
	}

	serverExplicit := flags.Lookup("server").Changed
	profileExplicit := flags.Lookup("profile").Changed
	configExplicit := flags.Lookup("config").Changed
	passwordFlagExplicit := flags.Lookup("password").Changed

	// Restore profile from the highest-priority source so that CLI/env beat the
	// config file, matching the documented precedence.
	if profileSource := highestPriorityProfile(args, envValues); profileSource != "" {
		cfg.Profile = profileSource
	}
	cfg.Profile = strings.ToLower(strings.TrimSpace(cfg.Profile))

	// A daemon child must never daemonize again, even if the configuration
	// file or environment sets daemon=true.
	if os.Getenv(daemonChildEnvVar) == "1" {
		cfg.Daemon = false
	}

	if subcommand == "connect" {
		if err := resolveConnectPassword(&cfg, passwordFlagExplicit); err != nil {
			return startupOptions{}, flags, err
		}
		if cfg.ServerAddress == "" && !profileExplicit && !configExplicit && !serverExplicit {
			return startupOptions{}, flags, errors.New("BUAAConnect: server address is required; specify --profile school, --profile act, --config, or --server")
		}
	}

	options.Config = cfg
	return options, flags, nil
}

func loadEnvPrefix(k *koanf.Koanf, envValues []string, prefix string, allowedKeys map[string]struct{}) error {
	provider := env.Provider(".", env.Opt{
		Prefix:      prefix,
		EnvironFunc: func() []string { return envValues },
		TransformFunc: func(key, value string) (string, any) {
			key = strings.ToLower(strings.TrimPrefix(key, prefix))
			if key == "config" || isCollectionEnvKey(key) || key == "daemon_child" {
				return "", nil
			}
			return key, value
		},
	})
	if err := k.Load(provider, nil); err != nil {
		return fmt.Errorf("load environment %s: %w", prefix, err)
	}
	if err := normalizeConfigAliases(k); err != nil {
		return fmt.Errorf("load environment %s: %w", prefix, err)
	}
	if err := rejectUnknownKeys(k, allowedKeys); err != nil {
		return fmt.Errorf("load environment %s: %w", prefix, err)
	}
	return nil
}

func highestPriorityProfile(args []string, envValues []string) string {
	if p, ok := parseFlagValue(args, "profile"); ok && p != "" {
		return p
	}
	if p, ok := lookupEnvironment(envValues, buaaEnvPrefix+"PROFILE"); ok && p != "" {
		return p
	}
	if p, ok := lookupEnvironment(envValues, envPrefix+"PROFILE"); ok && p != "" {
		return p
	}
	return ""
}

func parseFlagValue(args []string, name string) (string, bool) {
	prefix := "--" + name + "="
	short := "-" + name + "="
	for i, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix), true
		}
		if strings.HasPrefix(arg, short) {
			return strings.TrimPrefix(arg, short), true
		}
		if arg == "--"+name || arg == "-"+name {
			if i+1 < len(args) {
				return args[i+1], true
			}
		}
	}
	return "", false
}

func peekProfileFromConfig(path string) (string, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider(path), toml.Parser()); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(k.String("profile"))), nil
}

func normalizeLegacyArgs(flags *pflag.FlagSet, args []string) []string {
	normalized := append([]string(nil), args...)
	expectValue := false
	stopParsing := false
	for i, arg := range normalized {
		if stopParsing {
			continue
		}
		if expectValue {
			expectValue = false
			continue
		}
		if arg == "--" {
			stopParsing = true
			continue
		}
		if arg == "-h" {
			normalized[i] = "--help"
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		hasValue := false
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
			hasValue = true
		}
		flag := flags.Lookup(name)
		if flag != nil && !strings.HasPrefix(arg, "--") {
			normalized[i] = "-" + arg
		}
		if flag != nil && flag.NoOptDefVal == "" && !hasValue {
			expectValue = true
		}
	}
	return normalized
}

func lookupEnvironment(environ []string, name string) (string, bool) {
	prefix := name + "="
	for _, item := range environ {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix), true
		}
	}
	return "", false
}

func rejectUnknownKeys(k *koanf.Koanf, allowed map[string]struct{}) error {
	for _, key := range k.Keys() {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown configuration key %q", key)
		}
	}
	return nil
}

func normalizeConfigAliases(k *koanf.Koanf) error {
	for _, alias := range configAliases {
		if k.Exists(alias.LegacyKey) {
			if err := k.Set(alias.CanonicalKey, k.Get(alias.LegacyKey)); err != nil {
				return err
			}
		}
		k.Delete(alias.LegacyKey)
	}
	return nil
}

func isCollectionEnvKey(key string) bool {
	for _, spec := range collectionSpecs {
		if string(spec.Key) == key {
			return true
		}
	}
	return false
}

func configKeyForFlag(name string) (string, bool) {
	for _, alias := range configAliases {
		if name == alias.LegacyFlag || name == alias.CanonicalFlag {
			return alias.CanonicalKey, true
		}
	}
	switch name {
	case "config", "version", "auth-info", "trust-device", "untrust-device",
		"profile", "probe":
		return "", false
	case "server":
		return "server_address", true
	case "port":
		return "server_port", true
	case "extra-route":
		return "", false // handled manually after unmarshal
	}
	for _, spec := range collectionSpecs {
		if spec.FlagName == name {
			return "", false
		}
	}
	return strings.ReplaceAll(name, "-", "_"), true
}

type collectionValue struct {
	Value string
	Set   bool
}

type collectionValues map[collectionKey]collectionValue

func collectionValuesFromEnvironment(environ []string) collectionValues {
	values := make(collectionValues, len(collectionSpecs))
	for _, spec := range collectionSpecs {
		var value string
		var set bool
		if value, set = lookupEnvironment(environ, buaaEnvPrefix+spec.EnvName); !set {
			value, set = lookupEnvironment(environ, envPrefix+spec.EnvName)
		}
		values[spec.Key] = collectionValue{Value: value, Set: set}
	}
	return values
}

func collectionValuesFromFlags(flags *pflag.FlagSet) collectionValues {
	values := make(collectionValues, len(collectionSpecs))
	for _, spec := range collectionSpecs {
		flag := flags.Lookup(spec.FlagName)
		values[spec.Key] = collectionValue{Value: flag.Value.String(), Set: flag.Changed}
	}
	return values
}

func applyCollectionValues(k *koanf.Koanf, values collectionValues) error {
	tcp := values[collectionTCPPortForwarding]
	udp := values[collectionUDPPortForwarding]
	if tcp.Set || udp.Set {
		var entries []configs.SinglePortForwarding
		for _, item := range []struct {
			value   collectionValue
			network string
		}{
			{tcp, "tcp"},
			{udp, "udp"},
		} {
			parsed, err := parsePortForwarding(item.network, item.value.Value)
			if err != nil {
				return err
			}
			entries = append(entries, parsed...)
		}
		if err := k.Set("port_forwarding", entries); err != nil {
			return err
		}
	}

	customDNS := values[collectionCustomDNS]
	if customDNS.Set {
		entries, err := parseCustomDNS(customDNS.Value)
		if err != nil {
			return err
		}
		if err := k.Set("custom_dns", entries); err != nil {
			return err
		}
	}

	proxyDomains := values[collectionProxyDomain]
	if proxyDomains.Set {
		entries := parseProxyDomains(proxyDomains.Value)
		if err := k.Set("custom_proxy_domain", entries); err != nil {
			return err
		}
	}
	return nil
}

func splitExtraRoutes(value string) []string {
	if value == "" {
		return nil
	}
	var out []string
	for _, r := range strings.Split(value, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

func normalizeExtraRoutes(cfg *configs.Config) error {
	var normalized []string
	seen := make(map[string]struct{})
	for _, raw := range cfg.ExtraRoutes {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			prefix, err := configs.NormalizeExtraRoute(part)
			if err != nil {
				return err
			}
			key := prefix.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			normalized = append(normalized, key)
		}
	}
	cfg.ExtraRoutes = normalized
	return nil
}

func parsePortForwarding(network, value string) ([]configs.SinglePortForwarding, error) {
	if value == "" {
		return nil, nil
	}
	var entries []configs.SinglePortForwarding
	for _, forwarding := range strings.Split(value, ",") {
		addresses := strings.SplitN(forwarding, "-", 2)
		if len(addresses) != 2 || addresses[0] == "" || addresses[1] == "" {
			return nil, fmt.Errorf("BUAAConnect: wrong %s port forwarding format", network)
		}
		entries = append(entries, configs.SinglePortForwarding{
			NetworkType:   network,
			BindAddress:   addresses[0],
			RemoteAddress: addresses[1],
		})
	}
	return entries, nil
}

func parseCustomDNS(value string) ([]configs.SingleCustomDNS, error) {
	if value == "" {
		return nil, nil
	}
	var entries []configs.SingleCustomDNS
	for _, entry := range strings.Split(value, ",") {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, errors.New("BUAAConnect: wrong custom dns format")
		}
		entries = append(entries, configs.SingleCustomDNS{HostName: parts[0], IP: parts[1]})
	}
	return entries, nil
}

func parseProxyDomains(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func zjuServerWorkaround(cfg *configs.Config) {
	if cfg.Protocol == "atrust" && cfg.ServerAddress == "rvpn.zju.edu.cn" {
		fmt.Println("BUAAConnect: set default aTrust server address to vpn.zju.edu.cn")
		cfg.ServerAddress = "vpn.zju.edu.cn"
	} else if cfg.Protocol == "easyconnect" && cfg.ServerAddress == "vpn.zju.edu.cn" {
		fmt.Println("BUAAConnect: set default EasyConnect server address to rvpn.zju.edu.cn")
		cfg.ServerAddress = "rvpn.zju.edu.cn"
	}
}

func validateConfig(cfg configs.Config) error {
	if cfg.Protocol != "easyconnect" && cfg.Protocol != "atrust" {
		return fmt.Errorf("unsupported VPN protocol: %s", cfg.Protocol)
	}
	if cfg.ServerPort < 1 || cfg.ServerPort > 65535 {
		return fmt.Errorf("invalid VPN server port: %d", cfg.ServerPort)
	}
	if cfg.SystemDNS != "auto" && cfg.SystemDNS != "resolvectl" && cfg.SystemDNS != "off" {
		return fmt.Errorf("invalid system-dns mode %q (expected auto, resolvectl, off)", cfg.SystemDNS)
	}
	for _, forwarding := range cfg.PortForwardingList {
		if forwarding.NetworkType == "" {
			return errors.New("BUAAConnect: network type is not set")
		}
		if forwarding.BindAddress == "" {
			return errors.New("BUAAConnect: bind address is not set")
		}
		if forwarding.RemoteAddress == "" {
			return errors.New("BUAAConnect: remote address is not set")
		}
	}
	for _, entry := range cfg.CustomDNSList {
		if entry.HostName == "" {
			return errors.New("BUAAConnect: host name is not set")
		}
		if entry.IP == "" {
			return errors.New("BUAAConnect: IP is not set")
		}
	}
	for _, domain := range cfg.CustomProxyDomain {
		if !domainPattern.MatchString(domain) {
			return fmt.Errorf("BUAAConnect: %s is not a valid domain", domain)
		}
	}
	return nil
}

func validateConnectConfig(cfg configs.Config, serverExplicit, profileExplicit, configExplicit bool) error {
	if cfg.ServerAddress == "" && !profileExplicit && !configExplicit && !serverExplicit {
		return errors.New("BUAAConnect: server address is required; specify --profile school, --profile act, --config, or --server")
	}
	if cfg.Protocol == "easyconnect" {
		if (cfg.Username == "" || cfg.Password == "") && cfg.TwfID == "" {
			return errors.New("BUAAConnect: missing required arguments")
		}
		return nil
	}

	var primaryCredentialsPresent bool
	switch cfg.AuthType {
	case "auth/psw":
		primaryCredentialsPresent = cfg.Username != "" && cfg.Password != ""
	case "auth/smsCheckCode":
		primaryCredentialsPresent = cfg.Phone != ""
	default:
		return nil
	}
	debugCredentialsPresent := cfg.SID != "" && cfg.DeviceID != "" && cfg.ResourceFile != ""
	if !primaryCredentialsPresent && !debugCredentialsPresent {
		return errors.New("BUAAConnect: missing required arguments")
	}
	return nil
}

func defaultReadPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr)
	return string(bytes), nil
}

func resolveConnectPassword(cfg *configs.Config, passwordFlagExplicit bool) error {
	if cfg.Password != "" {
		return nil
	}
	if cfg.Protocol == "easyconnect" && cfg.TwfID != "" {
		return nil
	}
	if cfg.Protocol == "atrust" {
		if cfg.AuthType != "auth/psw" {
			return nil
		}
		if cfg.Username == "" {
			return nil
		}
	}
	if cfg.Protocol == "easyconnect" && cfg.Username == "" {
		return nil
	}
	if passwordFlagExplicit {
		return errors.New("BUAAConnect: --password requires a non-empty value")
	}

	// When running as a daemon child, the parent passed the password via stdin.
	if os.Getenv(daemonChildEnvVar) == "1" {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read password from daemon pipe: %w", err)
		}
		cfg.Password = strings.TrimSpace(line)
		return nil
	}

	pass, err := stdinPasswordReader()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	cfg.Password = pass
	return nil
}

func initialize(args []string) int {
	options, flags, err := loadStartupOptions(args, os.Environ)
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if options.ShowVersion || options.Subcommand == "version" {
		fmt.Printf("BUAAConnect %s\n", zjuConnectVersionString())
		return 0
	}

	conf = options.Config

	// Security warning when the user exposes the password on the command line.
	if flags.Lookup("password").Changed {
		fmt.Fprintln(os.Stderr, "Warning: passing --password on the command line exposes your password in shell history and process listings. Use an environment variable or interactive prompt instead.")
	}

	if options.AuthInfo {
		if conf.Protocol != "atrust" {
			fmt.Fprintln(os.Stderr, "Auth info is only supported by the atrust protocol")
			return 1
		}
		log.SetOutput(io.Discard)
		info, err := atrust.GetAuthInfoList(conf.ServerAddress, conf.ServerPort, conf.BindInterface, conf.AutoDetectInterface, conf.LocalDNSServer, conf.DebugTLSLogFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get auth info list error:", err)
			return 1
		}
		jsonInfo, err := json.Marshal(info)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error marshaling auth info:", err)
			return 1
		}
		fmt.Println(string(jsonInfo))
		return 0
	}

	if options.TrustDevice || options.UntrustDevice {
		if conf.Protocol != "atrust" {
			fmt.Fprintln(os.Stderr, "Trust/Untrust device is only supported by the atrust protocol")
			return 1
		}
		if conf.ClientDataFile == "" {
			fmt.Fprintln(os.Stderr, "Client data file is required for trust/untrust device")
			return 1
		}
		clientData, err := os.ReadFile(conf.ClientDataFile)
		if err != nil {
			log.Printf("Read client data file error: %s", err)
			return 1
		}
		if err := atrust.SetTrusted(conf.ServerAddress, conf.ServerPort, clientData, options.TrustDevice, conf.BindInterface, conf.AutoDetectInterface, conf.LocalDNSServer, conf.DebugTLSLogFile); err != nil {
			fmt.Fprintln(os.Stderr, "Trust/Untrust device error:", err)
			return 1
		}
		if options.TrustDevice {
			log.Println("Device trusted successfully")
		} else {
			log.Println("Device untrusted successfully")
		}
		return 0
	}

	switch options.Subcommand {
	case "status":
		return runStatus(conf.StateDir, options.ProbeTarget)
	case "disconnect":
		return runDisconnect(conf.StateDir)
	case "doctor":
		return runDoctor(conf, options.ProbeTarget)
	case "connect", "":
		return runConnect(options, flags, args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", options.Subcommand)
		return 1
	}
}

var secretFlags = []string{
	"password",
	"cert-password",
	"totp-secret",
	"socks-passwd",
	"sign-key",
	"oauth2-code",
	"cas-ticket",
	"sid",
	"device-id",
	"twf-id",
}

func filterSecretArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, hasValue := flagNameFromArg(arg)
		if isSecretFlag(name) {
			if !hasValue && (arg == "--"+name || arg == "-"+name) {
				i++ // skip the separate value argument
			}
			continue
		}
		out = append(out, arg)
	}
	return out
}

func flagNameFromArg(arg string) (string, bool) {
	stripped := arg
	if strings.HasPrefix(stripped, "--") {
		stripped = strings.TrimPrefix(stripped, "--")
	} else if strings.HasPrefix(stripped, "-") {
		stripped = strings.TrimPrefix(stripped, "-")
	} else {
		return "", false
	}
	if idx := strings.IndexByte(stripped, '='); idx >= 0 {
		return stripped[:idx], true
	}
	return stripped, false
}

func isSecretFlag(name string) bool {
	for _, s := range secretFlags {
		if name == s {
			return true
		}
	}
	return false
}

func runStatus(stateDir, probeTarget string) int {
	mgr, err := runtime.NewManager(stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Status error:", err)
		return 1
	}
	text, err := mgr.StatusText(probeTarget)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Status error:", err)
		return 1
	}
	fmt.Print(text)
	return 0
}

func runDisconnect(stateDir string) int {
	mgr, err := runtime.NewManager(stateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Disconnect error:", err)
		return 1
	}
	if err := mgr.Disconnect(10 * time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "Disconnect error:", err)
		return 1
	}
	fmt.Println("BUAAConnect disconnected.")
	return 0
}

func runDoctor(cfg configs.Config, probeTarget string) int {
	var forwards []doctor.PortForward
	for _, pf := range cfg.PortForwardingList {
		forwards = append(forwards, doctor.PortForward{
			NetworkType:   pf.NetworkType,
			BindAddress:   pf.BindAddress,
			RemoteAddress: pf.RemoteAddress,
		})
	}

	instanceRunning := false
	if mgr, err := runtime.NewManager(cfg.StateDir); err == nil {
		if status, err := mgr.FindInstance(); err == nil && status != nil {
			instanceRunning = status.Running
		}
	}

	report := doctor.Run(doctor.ExecProber{}, doctor.Config{
		SocksBind:       cfg.SocksBind,
		HTTPBind:        cfg.HTTPBind,
		DNSServerBind:   cfg.DNSServerBind,
		PortForwarding:  forwards,
		TUNInterface:    cfg.TunName,
		InstanceRunning: instanceRunning,
	})
	fmt.Print(doctor.FormatReport(report))
	if probeTarget != "" {
		result := probeTargetConnectivity(probeTarget)
		if result.Err != nil {
			fmt.Fprintf(os.Stderr, "Probe %s: failed (%v)\n", probeTarget, result.Err)
		} else {
			fmt.Printf("Probe %s: OK (%v)\n", probeTarget, result.Duration)
		}
	}
	if !report.OK {
		return 1
	}
	return 0
}

func probeTargetConnectivity(target string) struct {
	Duration time.Duration
	Err      error
} {
	start := time.Now()
	conn, err := netDialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return struct {
			Duration time.Duration
			Err      error
		}{time.Since(start), err}
	}
	_ = conn.Close()
	return struct {
		Duration time.Duration
		Err      error
	}{time.Since(start), nil}
}

func runConnect(options startupOptions, flags *pflag.FlagSet, args []string) int {
	cfg := options.Config

	if err := validateConnectConfig(cfg, false, false, false); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Please see: https://github.com/haoyuehx/BUAAConnect")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		flags.PrintDefaults()
		return 1
	}

	if cfg.Daemon && os.Getenv(daemonChildEnvVar) != "1" {
		return runDaemon(cfg, args)
	}

	mgr, err := runtime.NewManager(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Runtime state error:", err)
		return 1
	}
	if _, err := mgr.Acquire(cfg.Profile, cfg.Protocol, cfg.ServerAddress); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot start:", err)
		return 1
	}
	return -1
}

func runDaemon(cfg configs.Config, args []string) int {
	mgr, err := runtime.NewManager(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Daemon error:", err)
		return 1
	}
	status, err := mgr.FindInstance()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Daemon error:", err)
		return 1
	}
	if status != nil && status.Running {
		fmt.Fprintf(os.Stderr, "BUAAConnect is already running (pid %d).\n", status.State.PID)
		return 1
	}
	if status != nil && status.Stale {
		_ = mgr.Remove()
	}

	// Never pass the plaintext password on the child's command line.
	filteredArgs := filterSecretArgs(args)
	opts := runtime.DaemonOptions{}
	if cfg.Password != "" {
		opts.Password = cfg.Password
	}
	opts.ExtraEnv = append(opts.ExtraEnv, "BUAA_CONNECT_DAEMON_CHILD=1")

	cmd, err := mgr.StartDaemon(filteredArgs, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Daemon error:", err)
		return 1
	}

	fmt.Printf("BUAAConnect started in background (pid %d). Waiting for connection...\n", cmd.Process.Pid)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	state, err := mgr.WaitForPhase(ctx, runtime.PhaseConnected)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Daemon did not reach connected state:", err)
		return 1
	}
	fmt.Printf("Connected (pid %d, client IP %s). Logs: %s\n", state.PID, state.ClientIP, mgr.LogPath())
	return 0
}
