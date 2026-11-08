//go:build !tun

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/containers/winquit/pkg/winquit"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	easyconnectclient "github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/internal/keylog"
	"github.com/mythologyli/zju-connect/internal/netownership"
	buaaruntime "github.com/mythologyli/zju-connect/internal/runtime"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tcptunnel"
	"github.com/mythologyli/zju-connect/stack/tun"
	"github.com/mythologyli/zju-connect/underlay"
	"golang.org/x/crypto/pkcs12"
	"inet.af/netaddr"
)

var conf configs.Config

func main() {
	if exitCode := initialize(os.Args[1:]); exitCode >= 0 {
		os.Exit(exitCode)
	}

	log.Init()

	runtimeMgr, _ := buaaruntime.NewManager(conf.StateDir)
	abortWithCleanup := func(phase buaaruntime.Phase, authStatus, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		log.Println(msg)
		if runtimeMgr != nil {
			_ = runtimeMgr.UpdateState(func(s *buaaruntime.State) {
				s.Phase = phase
				if authStatus != "" {
					s.AuthStatus = authStatus
				}
				s.TunnelStatus = "down"
				s.LastError = msg
			})
		}
		_ = hook_func.ExecTerminalFunc(context.Background())
		os.Exit(1)
	}

	log.Println("Start BUAAConnect " + zjuConnectVersionString())
	if conf.DebugDump {
		log.EnableDebug()
	}
	if errs := hook_func.ExecInitialFunc(context.Background(), conf); errs != nil {
		for _, err := range errs {
			log.Printf("Initial BUAAConnect failed: %s", err)
		}
		os.Exit(1)
	}
	underlayDialer, underlayErr := underlay.New(underlay.Options{
		InterfaceName:  conf.BindInterface,
		AutoDetect:     conf.AutoDetectInterface,
		DebugPCAPFile:  conf.DebugPCAPFile,
		LocalDNSServer: conf.LocalDNSServer,
	})
	if underlayErr != nil {
		abortWithCleanup(buaaruntime.PhaseError, "failed", "Create underlay dialer: %v", underlayErr)
	}
	tlsKeyLogWriter, tlsKeyLogErr := keylog.Open(conf.DebugTLSLogFile)
	if tlsKeyLogErr != nil {
		_ = underlayDialer.Close()
		abortWithCleanup(buaaruntime.PhaseError, "failed", "Create TLS key log: %v", tlsKeyLogErr)
	}
	if conf.DebugPCAPFile != "" {
		log.Printf("VPN underlay PCAP capture enabled: %s", conf.DebugPCAPFile)
	}
	if conf.DebugTLSLogFile != "" {
		log.Printf("TLS key logging enabled: %s", conf.DebugTLSLogFile)
	}
	if runtimeMgr != nil {
		_ = runtimeMgr.UpdatePhase(buaaruntime.PhaseAuthenticating, map[string]string{
			"auth_status": "authenticating",
		})
	}
	var vpnClient client.Client
	switch conf.Protocol {
	case "easyconnect":
		tlsCert := tls.Certificate{}
		if conf.CertFile != "" {
			p12Data, err := os.ReadFile(conf.CertFile)
			if err != nil {
				abortWithCleanup(buaaruntime.PhaseError, "failed", "Read certificate file error: %s", err)
			}

			key, cert, err := pkcs12.Decode(p12Data, conf.CertPassword)
			if err != nil {
				abortWithCleanup(buaaruntime.PhaseError, "failed", "Decode certificate file error: %s", err)
			}

			tlsCert = tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key.(crypto.PrivateKey),
				Leaf:        cert,
			}
		}

		vpnClient = easyconnectclient.NewClient(easyconnectclient.Options{
			Server: net.JoinHostPort(conf.ServerAddress, strconv.Itoa(conf.ServerPort)),
			Auth: easyconnectclient.AuthOptions{
				Username:      conf.Username,
				Password:      conf.Password,
				TOTPSecret:    conf.TOTPSecret,
				Certificate:   tlsCert,
				GraphCodeFile: conf.GraphCodeFile,
			},
			SessionID:     conf.TwfID,
			TestMultiLine: !conf.DisableMultiLine,
			Resources: easyconnectclient.ResourceOptions{
				Fetch:          !conf.DisableServerConfig,
				IncludeDomains: !conf.SkipDomainResource,
			},
			MaxReconnect:    conf.MaxReconnect,
			ReconnectDelay:  time.Duration(conf.ReconnectDelay) * time.Second,
			UnderlayDialer:  underlayDialer,
			TLSKeyLogWriter: tlsKeyLogWriter,
		})

		log.Printf("VPN protocol: %s", conf.Protocol)
		err := vpnClient.(*easyconnectclient.Client).Setup()
		if err != nil {
			vpnClient.(*easyconnectclient.Client).Close()
			_ = underlayDialer.Close()
			if tlsKeyLogWriter != nil {
				_ = tlsKeyLogWriter.Close()
			}
			abortWithCleanup(buaaruntime.PhaseError, "failed", "VPN client setup error: %s", err)
		}
		if vpnClient.CanUseTCPTunnel() {
			conf.TCPTunnelMode = true
		}
	case "atrust":
		var err error
		var resourceData []byte

		if conf.ResourceFile != "" {
			resourceData, err = os.ReadFile(conf.ResourceFile)
			if err != nil {
				abortWithCleanup(buaaruntime.PhaseError, "failed", "Read resource file error: %s", err)
			}
		}

		var clientData []byte
		if conf.ClientDataFile != "" {
			clientData, err = os.ReadFile(conf.ClientDataFile)
			if err != nil {
				log.Printf("Read client data file error: %s", err)
				log.Println("Will create a new client data file if log in successfully")
			}
			log.Printf("Client data will be saved to %s", conf.ClientDataFile)
		}

		var loginMethod auth.LoginMethod
		if conf.SID == "" || conf.DeviceID == "" || resourceData == nil {
			loginMethod, err = auth.NewLoginMethod(auth.LoginMethodOptions{
				AuthType:      conf.AuthType,
				Username:      conf.Username,
				Password:      conf.Password,
				Phone:         conf.Phone,
				Domain:        conf.LoginDomain,
				GraphCodeFile: conf.GraphCodeFile,
				CASTicket:     conf.CasTicket,
				OAuth2Code:    conf.OAuth2Code,
			})
			if err != nil {
				abortWithCleanup(buaaruntime.PhaseError, "failed", "Configure aTrust login: %v", err)
			}
		}

		vpnClient = atrustclient.NewClient(atrustclient.ClientOptions{
			Session: atrustclient.SessionOptions{
				Username:     conf.Username,
				SID:          conf.SID,
				DeviceID:     conf.DeviceID,
				MACAddresses: conf.MACAddresses,
				SignKey:      conf.SignKey,
			},
			MaxReconnect:    conf.MaxReconnect,
			ReconnectDelay:  time.Duration(conf.ReconnectDelay) * time.Second,
			UnderlayDialer:  underlayDialer,
			TLSKeyLogWriter: tlsKeyLogWriter,
		})

		var saveClientDataFunc func(data []byte) error
		if conf.ClientDataFile != "" {
			saveClientDataFunc = func(data []byte) error {
				return os.WriteFile(conf.ClientDataFile, data, 0600)
			}
		}

		log.Printf("VPN protocol: %s", conf.Protocol)
		clientData, err = vpnClient.(*atrustclient.Client).Setup(atrustclient.SetupOptions{
			ServerAddress:            conf.ServerAddress,
			ServerPort:               conf.ServerPort,
			LoginMethod:              loginMethod,
			TOTPSecret:               conf.TOTPSecret,
			ClientData:               clientData,
			ResourceData:             resourceData,
			BestNodesRefreshInterval: time.Duration(conf.UpdateBestNodesInterval) * time.Second,
			SessionRefreshInterval:   time.Duration(conf.SessionRefreshInterval) * time.Second,
			MaxReconnect:             conf.MaxReconnect,
			ReconnectDelay:           time.Duration(conf.ReconnectDelay) * time.Second,
			SaveClientData:           saveClientDataFunc,
		})
		if err != nil {
			vpnClient.(*atrustclient.Client).Close()
			_ = underlayDialer.Close()
			if tlsKeyLogWriter != nil {
				_ = tlsKeyLogWriter.Close()
			}
			abortWithCleanup(buaaruntime.PhaseError, "failed", "VPN client setup error: %s", err)
		}
	}

	log.Printf("VPN client started")
	if closer, ok := vpnClient.(interface{ Close() }); ok {
		hook_func.RegisterTerminalFunc("CloseVPNClient", func(ctx context.Context) error {
			closer.Close()
			return nil
		})
	}
	hook_func.RegisterTerminalFunc("CloseUnderlayDialer", func(ctx context.Context) error {
		return underlayDialer.Close()
	})
	if tlsKeyLogWriter != nil {
		hook_func.RegisterTerminalFunc("CloseTLSKeyLog", func(ctx context.Context) error {
			return tlsKeyLogWriter.Close()
		})
	}

	ipResources, err := vpnClient.IPResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP resources")
	}

	ipSet, err := vpnClient.IPSet()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP set")
	}

	domainResources, err := vpnClient.DomainResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No domain resources")
	}

	dnsResource, err := vpnClient.DNSResource()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No DNS resource")
	}

	if conf.Protocol == "easyconnect" {
		if !conf.DisableZJUConfig {
			if domainResources == nil {
				domainResources = make(client.DomainResources)
			}

			domainResources["zju.edu.cn"] = []client.DomainResource{{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}

			if ipResources == nil {
				ipResources = []client.IPResource{}
			}

			ipResources = append([]client.IPResource{{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}, ipResources...)

			ipSetBuilder := netaddr.IPSetBuilder{}
			if ipSet != nil {
				ipSetBuilder.AddSet(ipSet)
			}
			ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
			ipSet, _ = ipSetBuilder.IPSet()
		}

		for _, customProxyDomain := range conf.CustomProxyDomain {
			if domainResources != nil {
				domainResources[customProxyDomain] = append(domainResources[customProxyDomain], client.DomainResource{
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				})
			} else {
				domainResources = client.DomainResources{
					customProxyDomain: {{
						PortMin:  1,
						PortMax:  65535,
						Protocol: "all",
					}},
				}
			}
		}
	} else {
		for _, customProxyDomain := range conf.CustomProxyDomain {
			if domainResources != nil {
				domainResources[customProxyDomain] = append(domainResources[customProxyDomain], client.DomainResource{
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				})
			} else {
				domainResources = client.DomainResources{
					customProxyDomain: {{
						PortMin:  1,
						PortMax:  65535,
						Protocol: "all",
					}},
				}
			}
		}
	}

	var serverIPs []net.IP
	resolveHostIPs := func(host string) {
		if host == "" {
			return
		}
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
		if parsed := net.ParseIP(host); parsed != nil {
			serverIPs = append(serverIPs, parsed)
		} else if resolved, lookupErr := net.LookupIP(host); lookupErr == nil {
			serverIPs = append(serverIPs, resolved...)
		}
	}
	resolveHostIPs(conf.ServerAddress)
	if hoster, ok := vpnClient.(interface{ ServerHost() string }); ok {
		resolveHostIPs(hoster.ServerHost())
	}

	if len(conf.ExtraRoutes) > 0 && !conf.TUNMode {
		mergedRes, extraPrefixes, mergeErr := netownership.MergeExtraRoutes(ipResources, ipSet, conf.ExtraRoutes, serverIPs)
		if mergeErr != nil {
			abortWithCleanup(buaaruntime.PhaseError, "authenticated", "Invalid extra routes: %v", mergeErr)
		}
		ipResources = mergedRes
		if updatedSet, setErr := netownership.AppendExtraRoutesToIPSet(ipSet, extraPrefixes); setErr == nil {
			ipSet = updatedSet
		}
	}

	var vpnStack stack.Stack
	var vpnTUNStack *tun.Stack
	if conf.TCPTunnelMode {
		vpnStack, err = tcptunnel.NewStack(vpnClient)
		if err != nil {
			abortWithCleanup(buaaruntime.PhaseError, "authenticated", "TCP Tunnel stack setup error: %s", err)
		}
	} else if conf.TUNMode {
		vpnTUNStack, err = tun.NewStackWithOptions(vpnClient, tun.Options{
			TunName:     conf.TunName,
			DNSHijack:   conf.DNSHijack,
			FakeIP:      conf.FakeIP,
			IPResources: ipResources,
			ExtraRoutes: conf.ExtraRoutes,
			ServerIPs:   serverIPs,
			SystemDNS:   conf.SystemDNS,
			DNSDomains:  conf.CustomProxyDomain,
		})
		if err != nil {
			abortWithCleanup(buaaruntime.PhaseError, "authenticated", "TUN stack setup error (root/CAP_NET_ADMIN required): %s", err)
		}
		if len(conf.ExtraRoutes) > 0 {
			if mergedRes, _, mergeErr := netownership.MergeExtraRoutes(ipResources, ipSet, conf.ExtraRoutes, serverIPs); mergeErr == nil {
				ipResources = mergedRes
			}
		}

		if conf.AddRoute && ipSet != nil {
			for _, prefix := range ipSet.Prefixes() {
				skipServer := false
				for _, srvIP := range serverIPs {
					if addr, ok := netaddr.FromStdIP(srvIP); ok && prefix.Contains(addr) {
						skipServer = true
						break
					}
				}
				if skipServer {
					log.Printf("Skip route %s because it contains VPN server address", prefix.String())
					continue
				}
				log.Printf("Add route to %s", prefix.String())
				if routeErr := vpnTUNStack.AddRoute(prefix.String()); routeErr != nil {
					log.Printf("Warning: add route %s: %v", prefix.String(), routeErr)
				}
			}
		} else if !conf.AddRoute && !conf.DisableZJUConfig && conf.Protocol == "easyconnect" {
			log.Println("Add route to 10.0.0.0/8")
			_ = vpnTUNStack.AddRoute("10.0.0.0/8")
		}

		if conf.FakeIP {
			_ = vpnTUNStack.AddRoute("198.18.0.0/16")
		}

		vpnStack = vpnTUNStack
	} else {
		vpnStack, err = gvisor.NewStack(vpnClient)
		if err != nil {
			abortWithCleanup(buaaruntime.PhaseError, "authenticated", "gVisor stack setup error: %s", err)
		}
	}

	useRemoteDNS := !conf.DisableRemoteDNS
	remoteDNSServer := conf.RemoteDNSServer
	policyDNSServers, _ := vpnClient.DNSServers()
	if useRemoteDNS && remoteDNSServer == "auto" {
		remoteDNSServer, err = vpnClient.DNSServer()
		if err != nil {
			useRemoteDNS = false
			remoteDNSServer = ""
			log.Println("No DNS server provided by server. Disable remote DNS")
		} else {
			log.Printf("Use DNS server %s provided by server", remoteDNSServer)
		}
	}
	secondaryDNSServer := conf.SecondaryDNSServer
	if secondaryDNSServer == "auto" {
		secondaryDNSServer = "114.114.114.114"
		if len(policyDNSServers) > 1 {
			secondaryDNSServer = policyDNSServers[1]
			log.Printf("Use secondary DNS server %s provided by server", secondaryDNSServer)
		}
	}

	vpnResolver := resolve.NewResolver(
		vpnStack,
		remoteDNSServer,
		secondaryDNSServer,
		conf.DNSTTL,
		domainResources,
		dnsResource,
		useRemoteDNS,
	)
	hook_func.RegisterTerminalFunc("CloseResolver", func(ctx context.Context) error {
		vpnResolver.Close()
		return nil
	})

	for _, customDns := range conf.CustomDNSList {
		ipAddr := net.ParseIP(customDns.IP)
		if ipAddr == nil {
			log.Printf("Custom DNS for host name %s is invalid, SKIP", customDns.HostName)
			continue
		}
		vpnResolver.SetPermanentDNS(customDns.HostName, ipAddr)
		log.Printf("Add custom DNS: %s -> %s\n", customDns.HostName, customDns.IP)
	}
	localResolver := service.NewDnsServer(vpnResolver, []string{remoteDNSServer, secondaryDNSServer})
	vpnStack.SetupResolve(localResolver)
	vpnStack.SetupIPPool(vpnResolver.IPPool)

	go vpnStack.Run()

	if runtimeMgr != nil {
		hook_func.RegisterTerminalFunc("CleanupRuntimeState", func(ctx context.Context) error {
			return runtimeMgr.Remove()
		})
		_ = runtimeMgr.UpdateState(func(s *buaaruntime.State) {
			s.Phase = buaaruntime.PhaseConnected
			s.AuthStatus = "authenticated"
			if conf.TUNMode && vpnTUNStack != nil {
				s.TunnelStatus = "up"
				s.TunInterface = vpnTUNStack.InterfaceName()
				s.AddedRoutes = vpnTUNStack.AddedRoutes()
			} else {
				s.TunnelStatus = "proxy_only"
			}
			if clientIP, ipErr := vpnClient.IP(); ipErr == nil && clientIP != nil {
				s.ClientIP = clientIP.String()
			}
			s.UnderlayInterface = underlayDialer.InterfaceName()
			if remoteDNSServer != "" {
				s.DNSServers = []string{remoteDNSServer, secondaryDNSServer}
			} else if secondaryDNSServer != "" {
				s.DNSServers = []string{secondaryDNSServer}
			}
			s.SystemDNSMode = conf.SystemDNS
			s.SocksBind = conf.SocksBind
			s.HTTPBind = conf.HTTPBind
		})
	}

	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResources, conf.ProxyAll, conf.DialDirectProxy)

	if conf.DNSServerBind != "" {
		go service.ServeDNS(conf.DNSServerBind, localResolver)
	}
	if conf.TUNMode {
		clientIP, err := vpnClient.IP()
		if err != nil || clientIP == nil {
			log.Printf("Client IP unavailable, skip DNS binding: %v", err)
		} else {
			go service.ServeDNS(clientIP.String()+":53", localResolver)
		}
	}

	if conf.SocksBind != "" {
		go service.ServeSocks5(conf.SocksBind, vpnDialer, vpnResolver, conf.SocksUser, conf.SocksPasswd)
	}

	if conf.HTTPBind != "" {
		go service.ServeHTTP(conf.HTTPBind, vpnDialer)
	}

	if conf.ShadowsocksURL != "" {
		go service.ServeShadowsocks(vpnDialer, conf.ShadowsocksURL)
	}

	for _, portForwarding := range conf.PortForwardingList {
		switch portForwarding.NetworkType {
		case "tcp":
			go service.ServeTCPForwarding(vpnDialer.Dial, portForwarding.BindAddress, portForwarding.RemoteAddress)
		case "udp":
			go service.ServeUDPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		default:
			log.Printf("Port forwarding: unknown network type %s. Aborting", portForwarding.NetworkType)
		}
	}

	if !conf.DisableKeepAlive {
		if conf.KeepAliveURL == "" && !useRemoteDNS {
			log.Println("Keep alive is disabled because remote DNS is disabled, and no KeepAliveURL is provided")
		} else {
			keepAliveCtx, keepAliveCancel := context.WithCancel(context.Background())
			hook_func.RegisterTerminalFunc("CloseKeepAlive", func(ctx context.Context) error {
				keepAliveCancel()
				return nil
			})
			go service.KeepAlive(keepAliveCtx, vpnResolver, vpnDialer, conf.KeepAliveURL)
		}
	}

	var stackErrCh <-chan error
	if vpnTUNStack != nil {
		stackErrCh = vpnTUNStack.Err()
	}

	if runtime.GOOS == "windows" {
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT)
		winquit.SimulateSigTermOnQuit(done)
		select {
		case <-done:
		case err := <-stackErrCh:
			log.Printf("TUN stack stopped with error: %v", err)
		}
	} else {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		select {
		case <-quit:
		case err := <-stackErrCh:
			log.Printf("TUN stack stopped with error: %v", err)
		}
	}
	log.Println("Shutdown BUAAConnect ......")
	if errs := hook_func.ExecTerminalFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Printf("Shutdown BUAAConnect failed: %s", err)
		}
	} else {
		log.Println("Shutdown BUAAConnect success, Bye~")
	}
}
