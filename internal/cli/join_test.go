package cli

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestEligiblePeerEntriesExcludePeersWithoutUsableEndpoint(t *testing.T) {
	peers := map[string]json.RawMessage{
		"reachable":   json.RawMessage(`{"version":1,"node_id":"reachable","public_key":"key-a","tunnel_address":"10.90.0.2","listen_port":51820,"local_addresses":["192.168.1.20/24"]}`),
		"unreachable": json.RawMessage(`{"version":1,"node_id":"unreachable","public_key":"key-b","tunnel_address":"10.90.0.3","listen_port":51820,"local_addresses":["10.20.0.20/24"]}`),
	}

	entries, routes := eligiblePeerEntries([]string{"192.168.1.10/24"}, peers)
	if len(entries) != 1 || entries[0].id != "reachable" {
		t.Fatalf("eligible entries = %#v, want only reachable peer", entries)
	}
	if entries[0].endpoint != "192.168.1.20:51820" {
		t.Fatalf("endpoint = %q, want LAN endpoint", entries[0].endpoint)
	}
	if !reflect.DeepEqual(routes, []string{"10.90.0.2/32"}) {
		t.Fatalf("routes = %#v, want only configured peer route", routes)
	}
}

func TestDefaultNodeIDDropsLocalDomainSuffix(t *testing.T) {
	id, err := defaultNodeID("zero-m5-max.localdomain")
	if err != nil || id != "zero-m5-max" {
		t.Fatalf("defaultNodeID() = %q, %v; want zero-m5-max", id, err)
	}
	id, err = defaultNodeID("workstation")
	if err != nil || id != "workstation" {
		t.Fatalf("defaultNodeID() = %q, %v; want workstation", id, err)
	}
	if _, err := defaultNodeID(".localdomain"); err == nil {
		t.Fatal("empty hostname after suffix removal was accepted")
	}
}
