package orchestrator

// Live progress. CombinedOutput buffers a child's whole output until it exits,
// so a multi-minute tool run looks hung. Here we stream stdout/stderr as they
// come, tick a heartbeat during quiet stretches, and bracket each stage with
// timed banners. outMu serialises console writes so the concurrent ffuf
// goroutines never interleave a half-line.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// outMu serializes every write to stdout across all goroutines.
var outMu sync.Mutex

// banner prints one thread-safe status line to stdout.
func banner(format string, args ...any) {
	outMu.Lock()
	defer outMu.Unlock()
	fmt.Printf(format+"\n", args...)
}

// fmtElapsed renders a duration as a compact, whole-second string ("42s",
// "3m05s") for status lines.
func fmtElapsed(since time.Time) string {
	return time.Since(since).Round(time.Second).String()
}

// runStreaming runs cmd and relays its output live. Both pipes are always
// drained (an unread full pipe blocks the child), but only the requested
// streams are printed: nuclei's stdout just echoes the JSONL we already write
// to a file, so callers mute it and keep stderr. prefix tags concurrent ffuf
// jobs so their lines stay distinguishable.
func runStreaming(cmd *exec.Cmd, prefix string, printStdout, printStderr bool) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go streamLines(stdout, prefix, printStdout, &wg)
	go streamLines(stderr, prefix, printStderr, &wg)
	wg.Wait()

	return cmd.Wait()
}

// streamLines reads r line by line, printing each (if print is set) under the
// shared stdout lock so lines never interleave. It always reads to EOF so the
// child process is never blocked on a full pipe, even when muted.
func streamLines(r io.Reader, prefix string, print bool, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	// Tool output lines (nuclei especially) can be long; give the scanner room.
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		if !print {
			continue
		}
		line := scanner.Text()
		outMu.Lock()
		if prefix != "" {
			fmt.Fprintf(os.Stdout, "      %s | %s\n", prefix, line)
		} else {
			fmt.Fprintf(os.Stdout, "      %s\n", line)
		}
		outMu.Unlock()
	}
}

// heartbeat prints a periodic reassurance line while a stage runs, so a tool
// that goes quiet (nmap during host discovery, ffuf between hits) doesn't look
// hung. The message is produced by a callback so callers can fold in live
// state — e.g. how many ffuf targets have finished so far.
type heartbeat struct {
	stop chan struct{}
	done chan struct{}
}

// startHeartbeat begins ticking every interval, calling msg() to build each
// line. msg receives the elapsed-time string. Call Stop() to end it.
func startHeartbeat(interval time.Duration, msg func(elapsed string) string) *heartbeat {
	hb := &heartbeat{stop: make(chan struct{}), done: make(chan struct{})}
	start := time.Now()
	go func() {
		defer close(hb.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-hb.stop:
				return
			case <-t.C:
				banner("      … %s", msg(fmtElapsed(start)))
			}
		}
	}()
	return hb
}

// Stop halts the heartbeat and waits for its goroutine to exit.
func (h *heartbeat) Stop() {
	if h == nil {
		return
	}
	close(h.stop)
	<-h.done
}
