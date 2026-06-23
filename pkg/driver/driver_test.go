package driver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
)

func TestSanitizeLogObjectRedactsCSIRequestSecrets(t *testing.T) {
	req := &csi.NodeStageVolumeRequest{
		VolumeId:          "tank/pvc-1",
		StagingTargetPath: "/var/lib/kubelet/plugins/kubernetes.io/csi/pv/pvc-1/globalmount",
		Secrets: map[string]string{
			"apiKey": "super-secret-api-key",
		},
		PublishContext: map[string]string{
			PublishContextProtocol:   ProtocolNVMeOF,
			PublishContextNVMeSubNQN: "nqn.2011-06.com.truenas:csi-pvc-1",
		},
		VolumeContext: map[string]string{
			paramNVMeOFDHCHAPKey: "DHHC-1:01:host-secret:",
			"safe":               "visible",
		},
		VolumeCapability: mountCapability(csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER),
	}

	encoded := mustMarshalSanitized(t, sanitizeLogObject(req))
	for _, leaked := range []string{"super-secret-api-key", "DHHC-1:01:host-secret:"} {
		if strings.Contains(encoded, leaked) {
			t.Fatalf("sanitized request leaked %q in %s", leaked, encoded)
		}
	}
	if !strings.Contains(encoded, "redacted") {
		t.Fatalf("sanitized request did not contain redaction marker: %s", encoded)
	}
	if !strings.Contains(encoded, "visible") {
		t.Fatalf("sanitized request removed non-sensitive context: %s", encoded)
	}
}

func TestSanitizeLogObjectRedactsCSIResponseSecrets(t *testing.T) {
	resp := &csi.CreateVolumeResponse{
		Volume: &csi.Volume{
			VolumeId: "tank/pvc-1",
			VolumeContext: map[string]string{
				paramEncryptionPassphrase: "passphrase-secret",
				PublishContextTargetIQN:   "iqn.2000-01.io.truenas:pvc-1",
			},
		},
	}

	encoded := mustMarshalSanitized(t, sanitizeLogObject(resp))
	if strings.Contains(encoded, "passphrase-secret") {
		t.Fatalf("sanitized response leaked passphrase: %s", encoded)
	}
	if !strings.Contains(encoded, "iqn.2000-01.io.truenas:pvc-1") {
		t.Fatalf("sanitized response removed non-sensitive value: %s", encoded)
	}
}

func mustMarshalSanitized(t *testing.T, obj any) string {
	t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal sanitized object: %v", err)
	}
	return string(data)
}
