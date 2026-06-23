package driver

import (
	"strings"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
)

func testControllerServer() *ControllerServer {
	d := &Driver{}
	d.initializeCapabilities()
	return NewControllerServer(d)
}

func mountCapability(mode csi.VolumeCapability_AccessMode_Mode) *csi.VolumeCapability {
	return &csi.VolumeCapability{
		AccessMode: &csi.VolumeCapability_AccessMode{Mode: mode},
		AccessType: &csi.VolumeCapability_Mount{
			Mount: &csi.VolumeCapability_MountVolume{},
		},
	}
}

func TestValidateNVMeOFParametersRequiresHostNQNOrExplicitAllowAnyHost(t *testing.T) {
	err := validateNVMeOFParameters(ProtocolNVMeOF, map[string]string{
		paramProtocol: ProtocolNVMeOF,
	})
	if err == nil || !strings.Contains(err.Error(), paramNVMeOFHostNQN) {
		t.Fatalf("expected missing hostNQN error, got %v", err)
	}

	for name, params := range map[string]map[string]string{
		"host acl": {
			paramProtocol:        ProtocolNVMeOF,
			paramNVMeOFHostNQN:   "nqn.2014-08.org.nvmexpress:uuid:node-a",
			paramNVMeOFDHCHAPKey: "DHHC-1:01:key:",
		},
		"explicit unsafe opt in": {
			paramProtocol:            ProtocolNVMeOF,
			paramNVMeOFAllowAnyHost:  "true",
			paramNVMeOFDHCHAPHash:    "SHA-256",
			paramNVMeOFDHCHAPDHGroup: "2048-BIT",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateNVMeOFParameters(ProtocolNVMeOF, params); err != nil {
				t.Fatalf("validateNVMeOFParameters: %v", err)
			}
		})
	}
}

func TestValidateNVMeOFParametersRejectsAmbiguousOrInvalidAllowAnyHost(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{
			name: "host nqn and allow any host",
			params: map[string]string{
				paramProtocol:           ProtocolNVMeOF,
				paramNVMeOFHostNQN:      "nqn.host",
				paramNVMeOFAllowAnyHost: "true",
			},
			want: paramNVMeOFAllowAnyHost,
		},
		{
			name: "invalid boolean",
			params: map[string]string{
				paramProtocol:           ProtocolNVMeOF,
				paramNVMeOFAllowAnyHost: "yes",
			},
			want: "invalid " + paramNVMeOFAllowAnyHost,
		},
		{
			name: "dhchap without host nqn",
			params: map[string]string{
				paramProtocol:        ProtocolNVMeOF,
				paramNVMeOFDHCHAPKey: "DHHC-1:01:key:",
			},
			want: paramNVMeOFHostNQN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNVMeOFParameters(ProtocolNVMeOF, tt.params)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestNVMeOFAllowAnyHostStrictBool(t *testing.T) {
	got, err := nvmeOFAllowAnyHost(map[string]string{paramNVMeOFAllowAnyHost: "true"})
	if err != nil || !got {
		t.Fatalf("nvmeOFAllowAnyHost true = %v, %v", got, err)
	}

	got, err = nvmeOFAllowAnyHost(map[string]string{paramNVMeOFAllowAnyHost: "false"})
	if err != nil || got {
		t.Fatalf("nvmeOFAllowAnyHost false = %v, %v", got, err)
	}

	if _, err := nvmeOFAllowAnyHost(map[string]string{paramNVMeOFAllowAnyHost: "1"}); err == nil {
		t.Fatal("expected invalid bool error")
	}
}

func TestValidateVolumeCapabilitiesRejectsBlockProtocolMultiWriter(t *testing.T) {
	s := testControllerServer()
	cap := mountCapability(csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER)

	for _, protocol := range []string{ProtocolISCSI, ProtocolNVMeOF} {
		t.Run(protocol, func(t *testing.T) {
			err := s.validateVolumeCapabilities(protocol, []*csi.VolumeCapability{cap})
			if err == nil || !strings.Contains(err.Error(), "not supported for protocol") {
				t.Fatalf("expected protocol-specific error, got %v", err)
			}
		})
	}
}

func TestValidateVolumeCapabilitiesKeepsNFSRWX(t *testing.T) {
	s := testControllerServer()
	cap := mountCapability(csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER)

	if err := s.validateVolumeCapabilities(ProtocolNFS, []*csi.VolumeCapability{cap}); err != nil {
		t.Fatalf("expected NFS RWX to remain supported, got %v", err)
	}
}
