package configs

import "testing"

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Protocol != "easyconnect" {
		t.Fatalf("Protocol = %q, want easyconnect", cfg.Protocol)
	}
	if cfg.ServerAddress != "" {
		t.Fatalf("ServerAddress = %q, want derived default", cfg.ServerAddress)
	}
	if cfg.ServerPort != 443 {
		t.Fatalf("ServerPort = %d, want 443", cfg.ServerPort)
	}
	if cfg.SocksBind != ":1080" || cfg.HTTPBind != ":1081" {
		t.Fatalf("proxy defaults = %q, %q", cfg.SocksBind, cfg.HTTPBind)
	}
	if !cfg.DisableZJUConfig {
		t.Fatal("DisableZJUConfig = false, want true by default in BUAAConnect")
	}
}

func TestProfileDefaults(t *testing.T) {
	school, err := ProfileDefaults("school")
	if err != nil {
		t.Fatalf("ProfileDefaults(school): %v", err)
	}
	if school.ServerAddress != "vpn.buaa.edu.cn" || school.ServerPort != 443 || school.TunName != "buaa-school" || !school.TUNMode || !school.AddRoute {
		t.Fatalf("unexpected school profile: %+v", school)
	}

	act, err := ProfileDefaults("act")
	if err != nil {
		t.Fatalf("ProfileDefaults(act): %v", err)
	}
	if act.ServerAddress != "vpn.act.buaa.edu.cn" || act.ServerPort != 8443 || act.TunName != "buaa-act" || !act.TUNMode || !act.AddRoute {
		t.Fatalf("unexpected act profile: %+v", act)
	}

	if _, err := ProfileDefaults("zju"); err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestNormalizeExtraRoute(t *testing.T) {
	p1, err := NormalizeExtraRoute("10.212.0.5")
	if err != nil || p1.String() != "10.212.0.5/32" {
		t.Fatalf("NormalizeExtraRoute(10.212.0.5) = %v, %v", p1, err)
	}
	p2, err := NormalizeExtraRoute("10.212.1.5/24")
	if err != nil || p2.String() != "10.212.1.0/24" {
		t.Fatalf("NormalizeExtraRoute(10.212.1.5/24) = %v, %v", p2, err)
	}
	if _, err := NormalizeExtraRoute("invalid"); err == nil {
		t.Fatal("expected error for invalid route")
	}
}
