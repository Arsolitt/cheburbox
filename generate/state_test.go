package generate

import (
	"testing"
)

func TestServerStateStoreAndGetCredentials(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	vlessCreds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "test-uuid", Flow: "xtls-rprx-vision"},
		},
	}

	state.StoreInboundCredentials("server-a", "vless-in", vlessCreds)

	got, ok := state.GetInboundCredentials("server-a", "vless-in")
	if !ok {
		t.Fatal("expected credentials to be stored")
	}
	if got.Users["alice"].UUID != "test-uuid" {
		t.Errorf("UUID = %q, want test-uuid", got.Users["alice"].UUID)
	}
}

func TestServerStateMissingCredentials(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	_, ok := state.GetInboundCredentials("server-a", "vless-in")
	if ok {
		t.Fatal("expected no credentials for unknown server/inbound")
	}
}

func TestServerStateStoreAndGetPinSHA256(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StorePinSHA256("server-a", "hy2-in", "sha256=abcdef")

	got, ok := state.GetPinSHA256("server-a", "hy2-in")
	if !ok {
		t.Fatal("expected pin-sha256 to be stored")
	}
	if got != "sha256=abcdef" {
		t.Errorf("pin-sha256 = %q, want sha256=abcdef", got)
	}
}

func TestServerStateMissingPinSHA256(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	_, ok := state.GetPinSHA256("server-a", "hy2-in")
	if ok {
		t.Fatal("expected no pin-sha256 for unknown server/inbound")
	}
}

func TestServerStateStoreAndGetEndpoint(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StoreEndpoint("server-a", "1.2.3.4")

	got, ok := state.GetEndpoint("server-a")
	if !ok {
		t.Fatal("expected endpoint to be stored")
	}
	if got != "1.2.3.4" {
		t.Errorf("endpoint = %q, want 1.2.3.4", got)
	}
}

func TestServerStateEnsureUser(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StoreInboundType("server-a", "vless-in", inboundTypeVLESS)

	existingCreds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "alice-uuid", Flow: "xtls-rprx-vision"},
		},
	}
	state.StoreInboundCredentials("server-a", "vless-in", existingCreds)

	err := state.EnsureUser("server-a", "vless-in", "bob")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	creds, ok := state.GetInboundCredentials("server-a", "vless-in")
	if !ok {
		t.Fatal("expected credentials")
	}
	if _, exists := creds.Users["bob"]; !exists {
		t.Error("expected user bob to be added")
	}
	if creds.Users["alice"].UUID != "alice-uuid" {
		t.Error("existing user alice should be preserved")
	}
}

func TestServerStateEnsureUserExisting(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	existingCreds := InboundCredentials{
		Users: map[string]UserCreds{
			"alice": {UUID: "alice-uuid", Flow: "xtls-rprx-vision"},
		},
	}
	state.StoreInboundCredentials("server-a", "vless-in", existingCreds)

	err := state.EnsureUser("server-a", "vless-in", "alice")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}

	creds, _ := state.GetInboundCredentials("server-a", "vless-in")
	if creds.Users["alice"].UUID != "alice-uuid" {
		t.Error("existing user alice should keep original credentials")
	}
}

func TestServerStateEnsureUserNoInbound(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	err := state.EnsureUser("server-a", "vless-in", "alice")
	if err == nil {
		t.Fatal("expected error when ensuring user on non-existent inbound")
	}
}

func TestServerStateGetInboundType(t *testing.T) {
	t.Parallel()

	state := NewServerState()

	state.StoreInboundType("server-a", "vless-in", inboundTypeVLESS)
	state.StoreInboundType("server-a", "hy2-in", inboundTypeHysteria2)

	got, ok := state.GetInboundType("server-a", "vless-in")
	if !ok {
		t.Fatal("expected inbound type")
	}
	if got != inboundTypeVLESS {
		t.Errorf("inbound type = %q, want vless", got)
	}

	got, ok = state.GetInboundType("server-a", "hy2-in")
	if !ok {
		t.Fatal("expected inbound type")
	}
	if got != inboundTypeHysteria2 {
		t.Errorf("inbound type = %q, want hysteria2", got)
	}

	_, ok = state.GetInboundType("server-a", "nonexistent")
	if ok {
		t.Fatal("expected no inbound type for unknown inbound")
	}
}
