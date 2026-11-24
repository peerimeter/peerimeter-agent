package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"github.com/peerimeter/peerimeter-agent/internal/service"
)

func TestStatusSnapshotsIncludeNativeServiceState(t *testing.T) {
	snapshot := platform.Snapshot{NetworkID: "mesh", InterfaceName: "wg-mesh", State: "running"}
	serviceStatus := service.Status{Installed: true, Running: true}

	var single bytes.Buffer
	if err := writeStatusSnapshots(&single, []platform.Snapshot{snapshot}, serviceStatus, nil); err != nil {
		t.Fatal(err)
	}
	var singleResult struct {
		NetworkID        string `json:"network_id"`
		ServiceInstalled bool   `json:"service_installed"`
		ServiceRunning   bool   `json:"service_running"`
	}
	if err := json.Unmarshal(single.Bytes(), &singleResult); err != nil {
		t.Fatal(err)
	}
	if singleResult.NetworkID != "mesh" || !singleResult.ServiceInstalled || !singleResult.ServiceRunning {
		t.Fatalf("single-network status omitted service state: %+v", singleResult)
	}

	var multiple bytes.Buffer
	if err := writeStatusSnapshots(&multiple, []platform.Snapshot{snapshot, {NetworkID: "other"}}, serviceStatus, nil); err != nil {
		t.Fatal(err)
	}
	var multipleResult struct {
		Networks         []platform.Snapshot `json:"networks"`
		ServiceInstalled bool                `json:"service_installed"`
		ServiceRunning   bool                `json:"service_running"`
	}
	if err := json.Unmarshal(multiple.Bytes(), &multipleResult); err != nil {
		t.Fatal(err)
	}
	if len(multipleResult.Networks) != 2 || !multipleResult.ServiceInstalled || !multipleResult.ServiceRunning {
		t.Fatalf("multi-network status omitted service state: %+v", multipleResult)
	}
}

func TestStatusSnapshotsPreserveNetworkDataOnServiceInspectionError(t *testing.T) {
	var output bytes.Buffer
	snapshot := platform.Snapshot{NetworkID: "mesh", InterfaceName: "wg-mesh", State: "running"}
	inspectionErr := errors.New("systemctl unavailable")
	if err := writeStatusSnapshots(&output, []platform.Snapshot{snapshot}, service.Status{}, inspectionErr); err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if _, ok := result["network_id"]; !ok {
		t.Fatal("network status was lost when service inspection failed")
	}
	var gotError string
	if err := json.Unmarshal(result["service_status_error"], &gotError); err != nil || gotError != inspectionErr.Error() {
		t.Fatalf("service inspection error = %q, err=%v", gotError, err)
	}
	if _, ok := result["service_installed"]; ok {
		t.Fatal("failed inspection reported a false installed state")
	}
	var human bytes.Buffer
	if err := renderResponse(&human, output.Bytes(), false, 80); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human.String(), "Service installed: unknown") || !strings.Contains(human.String(), "Service status error: systemctl unavailable") {
		t.Fatalf("service inspection failure was not shown: %q", human.String())
	}
}

func TestRenderServiceStatus(t *testing.T) {
	var output bytes.Buffer
	if err := renderResponse(&output, []byte(`{"service_installed":true,"service_running":false}`), false, 80); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Service installed: yes") || !strings.Contains(output.String(), "Service running: no") {
		t.Fatalf("unexpected service status output: %q", output.String())
	}
}
