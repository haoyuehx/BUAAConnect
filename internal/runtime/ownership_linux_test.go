//go:build linux

package runtime

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// buildProcStat constructs a synthetic /proc/<pid>/stat line. starttime is
// placed at field 22 (1-indexed), i.e. fields[19] after the comm field, and
// vsize is placed at field 23 (fields[20]) so a parser reading fields[20]
// would return the wrong value.
func buildProcStat(pid int, comm string, starttime, vsize uint64) string {
	// Minimal required fields after comm:
	// state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
	// utime stime cutime cstime priority nice num_threads itrealvalue starttime
	// vsize rss ...
	return fmt.Sprintf(
		"%d (%s) S 1 1 1 0 -1 4194560 123 0 0 0 0 0 0 0 20 0 1 0 %d %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
		pid, comm, starttime, vsize,
	)
}

func TestParseProcStatStartTime(t *testing.T) {
	starttime := uint64(12345)
	vsize := uint64(99999999)
	data := buildProcStat(42, "buaaconnect", starttime, vsize)
	got, err := parseProcStatStartTime([]byte(data))
	if err != nil {
		t.Fatalf("parseProcStatStartTime error: %v", err)
	}
	if got != starttime {
		t.Fatalf("parseProcStatStartTime = %d, want %d", got, starttime)
	}

	// A parser reading fields[20] would mistake vsize for starttime. Ensure
	// that changing vsize does not change the parsed starttime.
	data2 := buildProcStat(42, "buaaconnect", starttime, vsize*2)
	got2, err := parseProcStatStartTime([]byte(data2))
	if err != nil {
		t.Fatalf("parseProcStatStartTime error: %v", err)
	}
	if got2 != starttime {
		t.Fatalf("parseProcStatStartTime changed when vsize changed: %d, want %d", got2, starttime)
	}
}

func TestParseProcStatStartTimeShortLine(t *testing.T) {
	data := "1 (comm) S 1 1 1 0 -1 4194560\n"
	if _, err := parseProcStatStartTime([]byte(data)); err == nil {
		t.Fatal("expected error for short /proc stat line")
	}
}

func TestIsSameProgramStableUnderMemoryGrowth(t *testing.T) {
	self, err := SelfInfo()
	if err != nil {
		t.Fatalf("SelfInfo: %v", err)
	}
	if !IsSameProgram(self.PID, self.StartTime, self.CmdLine) {
		t.Fatalf("IsSameProgram failed before allocation: starttime=%d cmdline=%q", self.StartTime, self.CmdLine)
	}

	// Allocate a large chunk of memory to change the process vsize. A parser
	// that incorrectly read vsize as starttime would now report a mismatch.
	buf := make([]byte, 128<<20)
	buf[0] = 1
	buf[len(buf)-1] = 1
	if !IsSameProgram(self.PID, self.StartTime, self.CmdLine) {
		t.Fatalf("IsSameProgram failed after allocation: starttime=%d cmdline=%q", self.StartTime, self.CmdLine)
	}
	runtime.KeepAlive(buf)
}

func TestSelfInfoCmdLineHasNoArguments(t *testing.T) {
	self, err := SelfInfo()
	if err != nil {
		t.Fatalf("SelfInfo: %v", err)
	}
	if self.CmdLine == "" {
		t.Fatal("CmdLine is empty")
	}
	// The recorded command line must be a single basename with no arguments.
	if len(strings.Fields(self.CmdLine)) != 1 {
		t.Fatalf("CmdLine contains arguments: %q", self.CmdLine)
	}
}
