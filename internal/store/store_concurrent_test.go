package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// TestConcurrentUpserts simulates RunFfufConcurrent hammering the same
// workspace from many goroutines at once (one per fuzzed target) and
// checks two things under `go test -race`:
//  1. No data race on the underlying maps (mutex actually protects them).
//  2. Dedup still holds under concurrency — inserting the same path from
//     20 goroutines at once must still end up as exactly ONE stored row.
func TestConcurrentUpserts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent-test.json")
	ws, err := Open(dbPath, "concurrency-project")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup

	// Every goroutine tries to insert the SAME path (simulates two ffuf
	// jobs racing to report the same hit) plus one UNIQUE path each
	// (simulates genuinely new findings arriving concurrently).
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := ws.UpsertPath(&WebPath{
				Host: "demo.local", URL: "https://demo.local/shared", StatusCode: 200, Length: 42,
			})
			if err != nil {
				t.Errorf("shared upsert: %v", err)
			}

			_, err = ws.UpsertPath(&WebPath{
				Host: "demo.local", URL: fmt.Sprintf("https://demo.local/unique-%d", i), StatusCode: 200, Length: 10,
			})
			if err != nil {
				t.Errorf("unique upsert: %v", err)
			}
		}(i)
	}
	wg.Wait()

	paths := ws.AllPaths()
	// Expect exactly 1 shared path + `goroutines` unique paths.
	want := 1 + goroutines
	if len(paths) != want {
		t.Errorf("stored paths = %d, want %d (dedup should collapse the shared URL to 1 row)", len(paths), want)
	}
}
