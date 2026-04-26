package links

import (
	"encoding/json"
	"net/url"
	"strconv"
	"testing"
)

func TestHysteria2Link(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		wantSNI  string
		wantObfs string
		wantPin  string
		wantALPN string
		info     InboundInfo
	}{
		{
			name: "full with all fields",
			info: InboundInfo{
				Server:       "server1",
				Endpoint:     "example.com",
				Tag:          "hy2",
				Type:         inboundTypeHysteria2,
				ListenPort:   443,
				UserName:     "alice",
				Password:     "secret123",
				ServerName:   "example.com",
				ObfsType:     "salamander",
				ObfsPassword: "obfs-pass",
				PinSHA256:    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				ALPN:         []string{"h3", "h2"},
			},
			wantSNI:  "example.com",
			wantObfs: "salamander",
			wantPin:  "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantALPN: "h3,h2",
		},
		{
			name: "without obfs",
			info: InboundInfo{
				Server:     "server2",
				Endpoint:   "proxy.example.com",
				Tag:        "hy2-no-obfs",
				Type:       inboundTypeHysteria2,
				ListenPort: 8443,
				UserName:   "bob",
				Password:   "pass456",
				ServerName: "proxy.example.com",
				PinSHA256:  "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
				ALPN:       []string{"h3"},
			},
			wantSNI:  "proxy.example.com",
			wantObfs: "",
			wantPin:  "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			wantALPN: "h3",
		},
		{
			name: "without pin-sha256",
			info: InboundInfo{
				Server:       "server3",
				Endpoint:     "node.example.com",
				Tag:          "hy2-no-pin",
				Type:         inboundTypeHysteria2,
				ListenPort:   443,
				UserName:     "carol",
				Password:     "pass789",
				ServerName:   "node.example.com",
				ObfsType:     "salamander",
				ObfsPassword: "obfs-secret",
				ALPN:         []string{"h3"},
			},
			wantSNI:  "node.example.com",
			wantObfs: "salamander",
			wantPin:  "",
			wantALPN: "h3",
		},
		{
			name: "without ALPN",
			info: InboundInfo{
				Server:     "server4",
				Endpoint:   "vpn.example.com",
				Tag:        "hy2-no-alpn",
				Type:       inboundTypeHysteria2,
				ListenPort: 443,
				UserName:   "dave",
				Password:   "passabc",
				ServerName: "vpn.example.com",
				PinSHA256:  "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			},
			wantSNI:  "vpn.example.com",
			wantObfs: "",
			wantPin:  "sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			wantALPN: "",
		},
		{
			name: "minimal with only required fields",
			info: InboundInfo{
				Server:     "server5",
				Endpoint:   "bare.example.com",
				Tag:        "hy2-min",
				Type:       inboundTypeHysteria2,
				ListenPort: 9000,
				UserName:   "eve",
				Password:   "minpass",
			},
			wantSNI:  "",
			wantObfs: "",
			wantPin:  "",
			wantALPN: "",
		},
		{
			name: "special chars in password",
			info: InboundInfo{
				Server:     "server6",
				Endpoint:   "special.example.com",
				Tag:        "hy2-special",
				Type:       inboundTypeHysteria2,
				ListenPort: 443,
				UserName:   "frank",
				Password:   "p@ss/w#rd",
				ServerName: "special.example.com",
			},
			wantSNI:  "special.example.com",
			wantObfs: "",
			wantPin:  "",
			wantALPN: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := Hysteria2Link(tt.info)

			parsed, err := url.Parse(result)
			if err != nil {
				t.Fatalf("failed to parse URI: %v", err)
			}

			if parsed.Scheme != hysteria2Scheme {
				t.Errorf("scheme = %q, want %q", parsed.Scheme, hysteria2Scheme)
			}

			// In hysteria2 URIs the password occupies the userinfo
			// "username" position (before @).
			gotPassword := parsed.User.Username()
			if gotPassword != tt.info.Password {
				t.Errorf("password = %q, want %q", gotPassword, tt.info.Password)
			}

			wantHost := tt.info.Endpoint + ":" + portString(tt.info.ListenPort)
			if parsed.Host != wantHost {
				t.Errorf("host = %q, want %q", parsed.Host, wantHost)
			}

			wantFragment := tt.info.Server + "-" + tt.info.Tag + "-" + tt.info.UserName
			if parsed.Fragment != wantFragment {
				t.Errorf("fragment = %q, want %q", parsed.Fragment, wantFragment)
			}

			query := parsed.Query()

			assertQueryParam(t, query, "sni", tt.wantSNI)
			assertQueryParam(t, query, "obfs", tt.wantObfs)

			if tt.wantObfs != "" {
				assertQueryParam(t, query, "obfs-password", tt.info.ObfsPassword)
			} else if query.Has("obfs-password") {
				t.Errorf("obfs-password should be absent when obfs is empty")
			}

			assertQueryParam(t, query, "pinSHA256", tt.wantPin)
			assertQueryParam(t, query, "alpn", tt.wantALPN)
		})
	}
}

func TestHysteria2OutboundJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		info      InboundInfo
		wantObfs  bool
		wantPin   bool
		wantError bool
	}{
		{
			name: "full with all fields",
			info: InboundInfo{
				Server:       "srv1",
				Endpoint:     "example.com",
				Tag:          "hy2",
				Type:         inboundTypeHysteria2,
				ListenPort:   443,
				UserName:     "alice",
				Password:     "secret123",
				ServerName:   "example.com",
				ObfsType:     "salamander",
				ObfsPassword: "obfs-pass",
				PinSHA256:    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				ALPN:         []string{"h3"},
			},
			wantObfs: true,
			wantPin:  true,
		},
		{
			name: "without obfs",
			info: InboundInfo{
				Server:     "srv2",
				Endpoint:   "proxy.example.com",
				Tag:        "hy2-no-obfs",
				Type:       inboundTypeHysteria2,
				ListenPort: 8443,
				UserName:   "bob",
				Password:   "pass456",
				ServerName: "proxy.example.com",
			},
			wantObfs: false,
			wantPin:  false,
		},
		{
			name: "without pin-sha256",
			info: InboundInfo{
				Server:       "srv3",
				Endpoint:     "node.example.com",
				Tag:          "hy2-no-pin",
				Type:         inboundTypeHysteria2,
				ListenPort:   443,
				UserName:     "carol",
				Password:     "pass789",
				ServerName:   "node.example.com",
				ObfsType:     "salamander",
				ObfsPassword: "obfs-secret",
			},
			wantObfs: true,
			wantPin:  false,
		},
		{
			name: "minimal without server name",
			info: InboundInfo{
				Server:     "srv4",
				Endpoint:   "bare.example.com",
				Tag:        "hy2-min",
				Type:       inboundTypeHysteria2,
				ListenPort: 9000,
				UserName:   "dave",
				Password:   "minpass",
			},
			wantObfs: false,
			wantPin:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := Hysteria2OutboundJSON(tt.info)

			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var parsed map[string]json.RawMessage

			if err = json.Unmarshal([]byte(result), &parsed); err != nil {
				t.Fatalf("invalid JSON output: %v", err)
			}

			assertJSONString(t, parsed, "type", inboundTypeHysteria2)

			wantTag := tt.info.Server + "-" + tt.info.Tag + "-" + tt.info.UserName
			assertJSONString(t, parsed, "tag", wantTag)
			assertJSONString(t, parsed, "server", tt.info.Endpoint)
			assertJSONString(t, parsed, "password", tt.info.Password)

			assertJSONNumber(t, parsed, "server_port", tt.info.ListenPort)

			if _, ok := parsed["tls"]; !ok {
				t.Fatalf("tls field missing from output")
			}

			var tlsMap map[string]json.RawMessage
			if err = json.Unmarshal(parsed["tls"], &tlsMap); err != nil {
				t.Fatalf("invalid tls JSON: %v", err)
			}

			var tlsEnabled bool
			if err = json.Unmarshal(tlsMap["enabled"], &tlsEnabled); err != nil {
				t.Fatalf("failed to parse tls.enabled: %v", err)
			}

			if !tlsEnabled {
				t.Errorf("tls.enabled = false, want true")
			}

			if tt.info.ServerName != "" {
				assertJSONStringInMap(t, tlsMap, "server_name", tt.info.ServerName)
			}

			if tt.wantObfs {
				if _, ok := parsed["obfs"]; !ok {
					t.Errorf("obfs field missing, expected it to be present")
				}
			} else {
				if _, ok := parsed["obfs"]; ok {
					t.Errorf("obfs field present, expected it to be absent")
				}
			}

			if tt.wantPin {
				if _, ok := tlsMap["certificate_public_key_sha256"]; !ok {
					t.Errorf("certificate_public_key_sha256 missing, expected it to be present")
				}
			} else {
				if _, ok := tlsMap["certificate_public_key_sha256"]; ok {
					t.Errorf("certificate_public_key_sha256 present, expected it to be absent")
				}
			}
		})
	}
}

func TestDecodePinSHA256(t *testing.T) {
	t.Parallel()

	t.Run("valid pin", func(t *testing.T) {
		t.Parallel()

		pin := "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

		decoded, err := decodePinSHA256(pin)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(decoded) == 0 {
			t.Errorf("decoded bytes should not be empty")
		}
	})

	t.Run("invalid prefix", func(t *testing.T) {
		t.Parallel()

		_, err := decodePinSHA256("sha256/")
		if err == nil {
			t.Errorf("expected error for empty base64 payload")
		}
	})

	t.Run("too short", func(t *testing.T) {
		t.Parallel()

		_, err := decodePinSHA256("short")
		if err == nil {
			t.Errorf("expected error for short pin")
		}
	})
}

// portString converts a port number to its string representation.
func portString(port uint16) string {
	return strconv.FormatUint(uint64(port), 10)
}

// assertQueryParam checks a URL query parameter value. If want is empty,
// it asserts the parameter is absent.
func assertQueryParam(t *testing.T, query url.Values, key string, want string) {
	t.Helper()

	if want == "" {
		if query.Has(key) {
			t.Errorf("query param %q should be absent, got %q", key, query.Get(key))
		}

		return
	}

	got := query.Get(key)
	if got != want {
		t.Errorf("query param %q = %q, want %q", key, got, want)
	}
}

// assertJSONString checks that a JSON field contains the expected string value.
func assertJSONString(t *testing.T, m map[string]json.RawMessage, key string, want string) {
	t.Helper()

	raw, ok := m[key]
	if !ok {
		t.Errorf("JSON field %q missing", key)

		return
	}

	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Errorf("JSON field %q is not a string: %v", key, err)

		return
	}

	if got != want {
		t.Errorf("JSON field %q = %q, want %q", key, got, want)
	}
}

// assertJSONStringInMap checks a string field inside a nested JSON map.
func assertJSONStringInMap(t *testing.T, m map[string]json.RawMessage, key string, want string) {
	t.Helper()

	assertJSONString(t, m, key, want)
}

// assertJSONNumber checks that a JSON field contains the expected numeric value.
func assertJSONNumber(t *testing.T, m map[string]json.RawMessage, key string, want uint16) {
	t.Helper()

	raw, ok := m[key]
	if !ok {
		t.Errorf("JSON field %q missing", key)

		return
	}

	var got float64
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Errorf("JSON field %q is not a number: %v", key, err)

		return
	}

	if uint16(got) != want {
		t.Errorf("JSON field %q = %v, want %v", key, uint16(got), want)
	}
}
