package configs

import (
	"fmt"
	"net/netip"
	"strings"
)

type ProfileName string

const (
	ProfileSchool ProfileName = "school"
	ProfileACT    ProfileName = "act"
)

type Config struct {
	// BUAA Profile & lifecycle fields
	Profile        string   `koanf:"profile"`
	TunName        string   `koanf:"tun_name"`
	ExtraRoutes    []string `koanf:"extra_routes"`
	SystemDNS      string   `koanf:"system_dns"` // "auto", "resolvectl", "off"
	Daemon         bool     `koanf:"daemon"`
	StateDir       string   `koanf:"state_dir"`
	MaxReconnect   int      `koanf:"max_reconnect"`
	ReconnectDelay int      `koanf:"reconnect_delay"`

	// Common fields
	Protocol            string                 `koanf:"protocol"`
	ServerAddress       string                 `koanf:"server_address"`
	ServerPort          int                    `koanf:"server_port"`
	Username            string                 `koanf:"username"`
	Password            string                 `koanf:"password"`
	TOTPSecret          string                 `koanf:"totp_secret"`
	SocksBind           string                 `koanf:"socks_bind"`
	SocksUser           string                 `koanf:"socks_user"`
	SocksPasswd         string                 `koanf:"socks_passwd"`
	HTTPBind            string                 `koanf:"http_bind"`
	PortForwardingList  []SinglePortForwarding `koanf:"port_forwarding"`
	ShadowsocksURL      string                 `koanf:"shadowsocks_url"`
	DialDirectProxy     string                 `koanf:"dial_direct_proxy"`
	DisableServerConfig bool                   `koanf:"disable_server_config"`
	DisableRemoteDNS    bool                   `koanf:"disable_remote_dns"`
	DNSTTL              uint64                 `koanf:"dns_ttl"`
	RemoteDNSServer     string                 `koanf:"remote_dns_server"`
	SecondaryDNSServer  string                 `koanf:"secondary_dns_server"`
	DNSServerBind       string                 `koanf:"dns_server_bind"`
	LocalDNSServer      string                 `koanf:"local_dns_server"`
	CustomDNSList       []SingleCustomDNS      `koanf:"custom_dns"`
	DisableKeepAlive    bool                   `koanf:"disable_keep_alive"`
	KeepAliveURL        string                 `koanf:"keep_alive_url"`
	TCPTunnelMode       bool                   `koanf:"tcp_tunnel_mode"`
	TUNMode             bool                   `koanf:"tun_mode"`
	AddRoute            bool                   `koanf:"add_route"`
	DNSHijack           bool                   `koanf:"dns_hijack"`
	ProxyAll            bool                   `koanf:"proxy_all"`
	FakeIP              bool                   `koanf:"fake_ip"`
	GraphCodeFile       string                 `koanf:"graph_code_file"`
	DebugDump           bool                   `koanf:"debug_dump"`
	DebugPCAPFile       string                 `koanf:"debug_pcap_file"`
	DebugTLSLogFile     string                 `koanf:"debug_tls_log_file"`
	BindInterface       string                 `koanf:"bind_interface"`
	AutoDetectInterface bool                   `koanf:"auto_detect_interface"`

	// EasyConnect fields
	CertFile           string   `koanf:"cert_file"`
	CertPassword       string   `koanf:"cert_password"`
	DisableZJUConfig   bool     `koanf:"disable_zju_config"`
	SkipDomainResource bool     `koanf:"skip_domain_resource"`
	DisableMultiLine   bool     `koanf:"disable_multi_line"`
	CustomProxyDomain  []string `koanf:"custom_proxy_domain"`
	TwfID              string   `koanf:"twf_id"`

	// aTrust fields
	AuthType                string   `koanf:"auth_type"`
	Phone                   string   `koanf:"phone"`
	LoginDomain             string   `koanf:"login_domain"`
	ClientDataFile          string   `koanf:"client_data_file"`
	CasTicket               string   `koanf:"cas_ticket"`
	OAuth2Code              string   `koanf:"oauth2_code"`
	SID                     string   `koanf:"sid"`
	DeviceID                string   `koanf:"device_id"`
	MACAddresses            []string `koanf:"mac_addresses"`
	SignKey                 string   `koanf:"sign_key"`
	ResourceFile            string   `koanf:"resource_file"`
	UpdateBestNodesInterval int      `koanf:"update_best_nodes_interval"`
	SessionRefreshInterval  int      `koanf:"session_refresh_interval"`
}

type SinglePortForwarding struct {
	NetworkType   string `koanf:"network_type"`
	BindAddress   string `koanf:"bind_address"`
	RemoteAddress string `koanf:"remote_address"`
}

type SingleCustomDNS struct {
	HostName string `koanf:"host_name"`
	IP       string `koanf:"ip"`
}

func Default() Config {
	return Config{
		Protocol:                "easyconnect",
		ServerPort:              443,
		SocksBind:               ":1080",
		HTTPBind:                ":1081",
		DNSTTL:                  3600,
		RemoteDNSServer:         "auto",
		SecondaryDNSServer:      "auto",
		LoginDomain:             "Radius",
		UpdateBestNodesInterval: 300,
		SessionRefreshInterval:  1800,
		DisableZJUConfig:        true,
		SystemDNS:               "auto",
		MaxReconnect:            5,
		ReconnectDelay:          3,
	}
}

// ProfileDefaults returns the built-in BUAA profile template for "school" or "act".
func ProfileDefaults(profile string) (Config, error) {
	cfg := Default()
	cfg.TUNMode = true
	cfg.AddRoute = true
	cfg.AutoDetectInterface = true
	cfg.SocksBind = "127.0.0.1:11080"
	cfg.HTTPBind = "127.0.0.1:11081"

	switch strings.ToLower(strings.TrimSpace(profile)) {
	case string(ProfileSchool):
		cfg.Profile = string(ProfileSchool)
		cfg.Protocol = "easyconnect"
		cfg.ServerAddress = "vpn.buaa.edu.cn"
		cfg.ServerPort = 443
		cfg.TunName = "buaa-school"
		return cfg, nil
	case string(ProfileACT):
		cfg.Profile = string(ProfileACT)
		cfg.Protocol = "easyconnect"
		cfg.ServerAddress = "vpn.act.buaa.edu.cn"
		cfg.ServerPort = 8443
		cfg.TunName = "buaa-act"
		return cfg, nil
	default:
		return Config{}, fmt.Errorf("unknown profile %q (expected %q or %q)", profile, ProfileSchool, ProfileACT)
	}
}

// NormalizeExtraRoute validates and normalizes an IP or CIDR string into a canonical IPv4 CIDR prefix.
func NormalizeExtraRoute(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty extra route")
	}
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid extra route CIDR %q: %w", raw, err)
		}
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("extra route %q must be IPv4", raw)
		}
		if prefix.Bits() < 8 {
			return netip.Prefix{}, fmt.Errorf("extra route %q is too broad (prefix length must be >= 8)", raw)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid extra route IP %q: %w", raw, err)
	}
	if !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("extra route %q must be IPv4", raw)
	}
	return netip.PrefixFrom(addr, 32), nil
}
