package links

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestVLESSLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		wantSecurity    string
		wantSNI         string
		wantFingerprint string
		wantPBK         string
		wantSID         string
		wantFlow        string
		wantFragment    string
		info            InboundInfo
	}{
		{
			name: "reality with all params",
			info: InboundInfo{
				Server:     "srv1",
				Endpoint:   "1.2.3.4",
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				UserName:   "alice",
				UUID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				Flow:       "xtls-rprx-vision",
				Reality: &RealityInfo{
					PublicKey: "pubkey123",
					ShortID:   "abcd1234",
					SNI:       "www.example.com",
				},
			},
			wantSecurity:    "reality",
			wantSNI:         "www.example.com",
			wantFingerprint: "chrome",
			wantPBK:         "pubkey123",
			wantSID:         "abcd1234",
			wantFlow:        "xtls-rprx-vision",
			wantFragment:    "srv1-vless-in-alice",
		},
		{
			name: "reality without short ID",
			info: InboundInfo{
				Server:     "srv2",
				Endpoint:   "5.6.7.8",
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 8443,
				UserName:   "bob",
				UUID:       "11111111-2222-3333-4444-555555555555",
				Flow:       "xtls-rprx-vision",
				Reality: &RealityInfo{
					PublicKey: "pubkey456",
					ShortID:   "",
					SNI:       "cdn.example.org",
				},
			},
			wantSecurity:    "reality",
			wantSNI:         "cdn.example.org",
			wantFingerprint: "chrome",
			wantPBK:         "pubkey456",
			wantSID:         "",
			wantFlow:        "xtls-rprx-vision",
			wantFragment:    "srv2-vless-in-bob",
		},
		{
			name: "plain TLS without reality",
			info: InboundInfo{
				Server:     "srv3",
				Endpoint:   "10.0.0.1",
				Tag:        "vless-tls",
				Type:       "vless",
				ListenPort: 443,
				UserName:   "carol",
				UUID:       "22222222-3333-4444-5555-666666666666",
				Flow:       "xtls-rprx-vision",
				ServerName: "tls.example.com",
			},
			wantSecurity: "tls",
			wantSNI:      "tls.example.com",
			wantFlow:     "xtls-rprx-vision",
			wantFragment: "srv3-vless-tls-carol",
		},
		{
			name: "no TLS",
			info: InboundInfo{
				Server:     "srv4",
				Endpoint:   "192.168.1.1",
				Tag:        "vless-plain",
				Type:       "vless",
				ListenPort: 1080,
				UserName:   "dave",
				UUID:       "33333333-4444-5555-6666-777777777777",
			},
			wantSecurity: "none",
			wantFragment: "srv4-vless-plain-dave",
		},
		{
			name: "empty flow omitted",
			info: InboundInfo{
				Server:     "srv5",
				Endpoint:   "10.10.10.10",
				Tag:        "vless-noflow",
				Type:       "vless",
				ListenPort: 443,
				UserName:   "eve",
				UUID:       "44444444-5555-6666-7777-888888888888",
				Flow:       "",
				Reality: &RealityInfo{
					PublicKey: "pubkey789",
					ShortID:   "ef012345",
					SNI:       "noflow.example.com",
				},
			},
			wantSecurity:    "reality",
			wantSNI:         "noflow.example.com",
			wantFingerprint: "chrome",
			wantPBK:         "pubkey789",
			wantSID:         "ef012345",
			wantFlow:        "",
			wantFragment:    "srv5-vless-noflow-eve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := VLESSLink(tt.info)
			parsed, err := url.Parse(result)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", result, err)
			}

			if parsed.Scheme != "vless" {
				t.Errorf("scheme = %q, want %q", parsed.Scheme, "vless")
			}

			if parsed.User.Username() != tt.info.UUID {
				t.Errorf("user = %q, want %q", parsed.User.Username(), tt.info.UUID)
			}

			if parsed.Hostname() != tt.info.Endpoint {
				t.Errorf("hostname = %q, want %q", parsed.Hostname(), tt.info.Endpoint)
			}

			query := parsed.Query()

			if got := query.Get("type"); got != "tcp" {
				t.Errorf("type = %q, want %q", got, "tcp")
			}

			if got := query.Get("security"); got != tt.wantSecurity {
				t.Errorf("security = %q, want %q", got, tt.wantSecurity)
			}

			if tt.wantSNI != "" {
				if got := query.Get("sni"); got != tt.wantSNI {
					t.Errorf("sni = %q, want %q", got, tt.wantSNI)
				}
			}

			if tt.wantFingerprint != "" {
				if got := query.Get("fp"); got != tt.wantFingerprint {
					t.Errorf("fp = %q, want %q", got, tt.wantFingerprint)
				}
			}

			if tt.wantPBK != "" {
				if got := query.Get("pbk"); got != tt.wantPBK {
					t.Errorf("pbk = %q, want %q", got, tt.wantPBK)
				}
			}

			if tt.wantSID != "" {
				if got := query.Get("sid"); got != tt.wantSID {
					t.Errorf("sid = %q, want %q", got, tt.wantSID)
				}
			} else if tt.info.Reality != nil && tt.info.Reality.ShortID == "" {
				if query.Has("sid") {
					t.Errorf("sid should be omitted when empty, got %q", query.Get("sid"))
				}
			}

			if tt.wantFlow != "" {
				if got := query.Get("flow"); got != tt.wantFlow {
					t.Errorf("flow = %q, want %q", got, tt.wantFlow)
				}
			} else {
				if query.Has("flow") {
					t.Errorf("flow should be omitted when empty, got %q", query.Get("flow"))
				}
			}

			gotFragment, err := url.PathUnescape(parsed.Fragment)
			if err != nil {
				t.Fatalf("unescape fragment: %v", err)
			}

			if gotFragment != tt.wantFragment {
				t.Errorf("fragment = %q, want %q", gotFragment, tt.wantFragment)
			}
		})
	}
}

func TestVLESSOutboundJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		wantTag     string
		wantFlow    string
		info        InboundInfo
		wantTLS     bool
		wantReality bool
	}{
		{
			name: "reality outbound",
			info: InboundInfo{
				Server:     "srv1",
				Endpoint:   "1.2.3.4",
				Tag:        "vless-in",
				Type:       "vless",
				ListenPort: 443,
				UserName:   "alice",
				UUID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
				Flow:       "xtls-rprx-vision",
				Reality: &RealityInfo{
					PublicKey: "pubkey123",
					ShortID:   "abcd1234",
					SNI:       "www.example.com",
				},
			},
			wantTag:     "srv1-vless-in-alice",
			wantTLS:     true,
			wantReality: true,
			wantFlow:    "xtls-rprx-vision",
		},
		{
			name: "plain TLS outbound",
			info: InboundInfo{
				Server:     "srv3",
				Endpoint:   "10.0.0.1",
				Tag:        "vless-tls",
				Type:       "vless",
				ListenPort: 443,
				UserName:   "carol",
				UUID:       "22222222-3333-4444-5555-666666666666",
				Flow:       "xtls-rprx-vision",
				ServerName: "tls.example.com",
			},
			wantTag:     "srv3-vless-tls-carol",
			wantTLS:     true,
			wantReality: false,
			wantFlow:    "xtls-rprx-vision",
		},
		{
			name: "no TLS outbound",
			info: InboundInfo{
				Server:     "srv4",
				Endpoint:   "192.168.1.1",
				Tag:        "vless-plain",
				Type:       "vless",
				ListenPort: 1080,
				UserName:   "dave",
				UUID:       "33333333-4444-5555-6666-777777777777",
			},
			wantTag:     "srv4-vless-plain-dave",
			wantTLS:     false,
			wantReality: false,
			wantFlow:    "",
		},
		{
			name: "empty flow omitted from JSON",
			info: InboundInfo{
				Server:     "srv5",
				Endpoint:   "10.10.10.10",
				Tag:        "vless-noflow",
				Type:       "vless",
				ListenPort: 443,
				UserName:   "eve",
				UUID:       "44444444-5555-6666-7777-888888888888",
				Flow:       "",
				Reality: &RealityInfo{
					PublicKey: "pubkey789",
					ShortID:   "ef012345",
					SNI:       "noflow.example.com",
				},
			},
			wantTag:     "srv5-vless-noflow-eve",
			wantTLS:     true,
			wantReality: true,
			wantFlow:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := VLESSOutboundJSON(tt.info)
			if err != nil {
				t.Fatalf("VLESSOutboundJSON(): %v", err)
			}

			var parsed map[string]json.RawMessage
			if err := json.Unmarshal([]byte(result), &parsed); err != nil {
				t.Fatalf("unmarshal result: %v", err)
			}

			var gotType string
			if err := json.Unmarshal(parsed["type"], &gotType); err != nil {
				t.Fatalf("unmarshal type: %v", err)
			}

			if gotType != "vless" {
				t.Errorf("type = %q, want %q", gotType, "vless")
			}

			var gotTag string
			if err := json.Unmarshal(parsed["tag"], &gotTag); err != nil {
				t.Fatalf("unmarshal tag: %v", err)
			}

			if gotTag != tt.wantTag {
				t.Errorf("tag = %q, want %q", gotTag, tt.wantTag)
			}

			var gotServer string
			if err := json.Unmarshal(parsed["server"], &gotServer); err != nil {
				t.Fatalf("unmarshal server: %v", err)
			}

			if gotServer != tt.info.Endpoint {
				t.Errorf("server = %q, want %q", gotServer, tt.info.Endpoint)
			}

			var gotPort uint16
			if err := json.Unmarshal(parsed["server_port"], &gotPort); err != nil {
				t.Fatalf("unmarshal server_port: %v", err)
			}

			if gotPort != tt.info.ListenPort {
				t.Errorf("server_port = %d, want %d", gotPort, tt.info.ListenPort)
			}

			var gotUUID string
			if err := json.Unmarshal(parsed["uuid"], &gotUUID); err != nil {
				t.Fatalf("unmarshal uuid: %v", err)
			}

			if gotUUID != tt.info.UUID {
				t.Errorf("uuid = %q, want %q", gotUUID, tt.info.UUID)
			}

			if tt.wantFlow != "" {
				var gotFlow string
				if err := json.Unmarshal(parsed["flow"], &gotFlow); err != nil {
					t.Fatalf("unmarshal flow: %v", err)
				}

				if gotFlow != tt.wantFlow {
					t.Errorf("flow = %q, want %q", gotFlow, tt.wantFlow)
				}
			} else {
				if _, ok := parsed["flow"]; ok {
					t.Errorf("flow should be omitted when empty, but it is present")
				}
			}

			if tt.wantTLS {
				if _, ok := parsed["tls"]; !ok {
					t.Fatalf("tls field expected but not present")
				}

				var tlsObj map[string]json.RawMessage
				if err := json.Unmarshal(parsed["tls"], &tlsObj); err != nil {
					t.Fatalf("unmarshal tls: %v", err)
				}

				var tlsEnabled bool
				if err := json.Unmarshal(tlsObj["enabled"], &tlsEnabled); err != nil {
					t.Fatalf("unmarshal tls.enabled: %v", err)
				}

				if !tlsEnabled {
					t.Errorf("tls.enabled = false, want true")
				}

				if tt.wantReality {
					if _, ok := tlsObj["reality"]; !ok {
						t.Fatalf("tls.reality expected but not present")
					}
				}
			} else {
				if _, ok := parsed["tls"]; ok {
					t.Errorf("tls field should be omitted when no TLS, but it is present")
				}
			}
		})
	}
}
