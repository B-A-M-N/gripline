package main

import (
	"sync"
	"testing"
)

type blockingObserverWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingObserverWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func TestJSONLObserverDroppedTotalIsMonotonic(t *testing.T) {
	writer := &blockingObserverWriter{started: make(chan struct{}), release: make(chan struct{})}
	observer := newJSONLObserver(writer)
	observer.enqueue(struct{ Type string }{Type: "first"})
	<-writer.started
	for i := 0; i < 2048; i++ {
		observer.enqueue(struct{ Type string }{Type: "overflow"})
	}
	before := observer.Stats().Dropped
	if before == 0 {
		t.Fatal("observer did not record queue overflow")
	}
	close(writer.release)
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	after := observer.Stats().Dropped
	if after != before {
		t.Fatalf("dropped total changed after reporting: before=%d after=%d", before, after)
	}
}
