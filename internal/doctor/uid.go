package doctor

import "os"

func osGetuidImpl() int {
	return os.Geteuid()
}
