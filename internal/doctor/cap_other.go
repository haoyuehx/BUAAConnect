//go:build !linux

package doctor

func hasLinuxCap(cap string) bool {
	return false
}

func osGeteuid() int {
	return osGetuidImpl()
}
