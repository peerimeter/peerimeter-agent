// Package helperprocess contains shared lifecycle checks for detached helpers.
package helperprocess

import (
	"encoding/json"
	"os"
	"os/exec"
	"time"
)

const (
	readinessTimeout  = 30 * time.Second
	readinessInterval = 50 * time.Millisecond
)

type result struct {
	State       string `json:"state"`
	HelperReady bool   `json:"helper_ready"`
}

// WaitUntilReady polls the helper result file and stops the child if it fails
// to report readiness before the bounded startup deadline.
func WaitUntilReady(cmd *exec.Cmd, resultPath string) bool {
	deadline := time.Now().Add(readinessTimeout)
	for time.Now().Before(deadline) {
		var response result
		data, err := os.ReadFile(resultPath)
		if err == nil && json.Unmarshal(data, &response) == nil {
			if response.HelperReady {
				return true
			}
			if response.State == "failed" {
				break
			}
		}
		time.Sleep(readinessInterval)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
	return false
}
