//go:build linux

package doctor

import (
	"os/exec"
	"strings"
)

func hasLinuxCap(cap string) bool {
	out, err := exec.Command("capsh", "--print").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), cap)
}

func osGeteuid() int {
	return osGetuidImpl()
}
