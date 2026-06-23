package driver

import "testing"

func TestParseISCSIConfigUsesDocumentedCHAPKeys(t *testing.T) {
	cfg, err := parseISCSIConfig(nil, map[string]string{
		paramISCSIChapUser:       "doc-user",
		paramISCSIChapSecret:     "doc-secret",
		paramISCSIChapPeerUser:   "doc-peer-user",
		paramISCSIChapPeerSecret: "doc-peer-secret",
	})
	if err != nil {
		t.Fatalf("parseISCSIConfig: %v", err)
	}

	if cfg.CHAPUsername != "doc-user" || cfg.CHAPPassword != "doc-secret" {
		t.Fatalf("documented CHAP keys not parsed: %+v", cfg)
	}
	if cfg.CHAPUsernameIn != "doc-peer-user" || cfg.CHAPPasswordIn != "doc-peer-secret" {
		t.Fatalf("documented mutual CHAP keys not parsed: %+v", cfg)
	}
}

func TestParseISCSIConfigFallsBackToLegacyCHAPKeys(t *testing.T) {
	cfg, err := parseISCSIConfig(nil, map[string]string{
		paramCHAPUsername:   "legacy-user",
		paramCHAPPassword:   "legacy-secret",
		paramCHAPUsernameIn: "legacy-peer-user",
		paramCHAPPasswordIn: "legacy-peer-secret",
	})
	if err != nil {
		t.Fatalf("parseISCSIConfig: %v", err)
	}

	if cfg.CHAPUsername != "legacy-user" || cfg.CHAPPassword != "legacy-secret" {
		t.Fatalf("legacy CHAP keys not parsed: %+v", cfg)
	}
	if cfg.CHAPUsernameIn != "legacy-peer-user" || cfg.CHAPPasswordIn != "legacy-peer-secret" {
		t.Fatalf("legacy mutual CHAP keys not parsed: %+v", cfg)
	}
}

func TestParseISCSIConfigPrefersDocumentedCHAPKeys(t *testing.T) {
	cfg, err := parseISCSIConfig(nil, map[string]string{
		paramISCSIChapUser:   "doc-user",
		paramISCSIChapSecret: "doc-secret",
		paramCHAPUsername:    "legacy-user",
		paramCHAPPassword:    "legacy-secret",
	})
	if err != nil {
		t.Fatalf("parseISCSIConfig: %v", err)
	}

	if cfg.CHAPUsername != "doc-user" || cfg.CHAPPassword != "doc-secret" {
		t.Fatalf("documented CHAP keys should win over legacy aliases: %+v", cfg)
	}
}
