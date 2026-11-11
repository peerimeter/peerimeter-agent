package uninstall

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"github.com/vishvananda/netlink"
	"os"
	"path/filepath"
	"strings"
)

func cleanupOwnedNetwork(ctx context.Context, p installstate.Profile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(p.StateDir, "ownership")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	if err := installstate.CheckFile(path); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(raw))
	decoded, e := hex.DecodeString(token)
	if e != nil || len(decoded) != 32 {
		return errors.New("cannot verify persisted native interface ownership")
	}
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, link := range links {
		if link.Attrs().Alias != "peerimeter:"+token {
			continue
		}
		if link.Type() != "wireguard" {
			return errors.New("owned interface marker is attached to an unexpected device type")
		}
		if err := netlink.LinkDel(link); err != nil {
			return errors.New("verified owned WireGuard interface could not be removed")
		}
	}
	return nil
}
func scheduleRemoval(removalPlan) (string, error) {
	return "", errors.New("deferred removal is only used on Windows")
}
