package proxy

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type immediateReadCloser struct {
	err error
}

func (b immediateReadCloser) Read([]byte) (int, error) { return 0, b.err }
func (b immediateReadCloser) Close() error             { return nil }

type blockingReadCloser struct {
	closed chan struct{}
}

func (b *blockingReadCloser) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("body closed")
}

func (b *blockingReadCloser) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

func TestIdleTimeoutReaderPreservesNonIdleStreamErrors(t *testing.T) {
	for name, want := range map[string]error{
		"eof":    io.EOF,
		"reset":  errors.New("stream reset"),
		"cancel": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			reader := newIdleTimeoutReader(immediateReadCloser{err: want}, time.Hour)
			_, err := reader.Read(make([]byte, 1))
			if !errors.Is(err, want) {
				t.Fatalf("Read error=%v, want %v", err, want)
			}
			if errors.Is(err, ErrStreamIdle) {
				t.Fatalf("%v was misclassified as idle timeout", want)
			}
		})
	}
}

func TestIdleTimeoutReaderReturnsDistinctIdleError(t *testing.T) {
	body := &blockingReadCloser{closed: make(chan struct{})}
	reader := newIdleTimeoutReader(body, 10*time.Millisecond)
	result := make(chan error, 1)
	go func() {
		_, err := reader.Read(make([]byte, 1))
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrStreamIdle) {
			t.Fatalf("idle read error=%v, want ErrStreamIdle", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle reader did not unblock after its deadline")
	}
	_ = reader.Close()
}
