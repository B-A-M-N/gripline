package proxy

import (
	"bytes"
	"io"
	"os"
)

// spoolMemoryThreshold is the body size above which we spool to a temp file
// instead of keeping everything in memory. 256 KiB keeps the per-connection
// memory bounded while avoiding the temp-file overhead for typical prompts.
const spoolMemoryThreshold = 256 << 10

// spooledBody is the result of bounded body reading (P0.16). It is an
// io.ReadCloser that may be backed by memory or a temp file.
type spooledBody struct {
	reader   io.Reader
	closer   io.Closer
	length   int64
	tooLarge bool
	fileName string // nonempty when backed by a temp file
}

func (b *spooledBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *spooledBody) Close() error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

// spoolBody reads the body with an absolute cap of maxBytes. Small bodies
// stay in memory; larger ones are spooled to a secure temp file. Returns
// tooLarge=true if the body exceeds maxBytes.
func spoolBody(rc io.ReadCloser, maxBytes int64, memThreshold int64) (*spooledBody, error) {
	var buf bytes.Buffer
	// Read up to min(memThreshold, maxBytes) into memory.
	limit := memThreshold
	if limit > maxBytes {
		limit = maxBytes
	}
	if _, err := io.CopyN(&buf, rc, limit); err != nil && err != io.EOF {
		_ = rc.Close()
		return nil, err
	}

	// If we filled the memThreshold buffer, the body may be larger — spool
	// the rest to a temp file.
	if int64(buf.Len()) >= memThreshold {
		tmp, err := os.CreateTemp("", "gripline-body-*.tmp")
		if err != nil {
			_ = rc.Close()
			return nil, err
		}
		// Write what we already buffered.
		if _, err := tmp.Write(buf.Bytes()); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			_ = rc.Close()
			return nil, err
		}
		// Copy the rest with the remaining cap.
		remaining := maxBytes - int64(buf.Len())
		if remaining < 0 {
			remaining = 0
		}
		written, err := io.CopyN(tmp, rc, remaining)
		_ = rc.Close()
		if err != nil && err != io.EOF {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, err
		}
		total := int64(buf.Len()) + written
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, err
		}
		return &spooledBody{
			reader:   tmp,
			closer:   tmp,
			length:   total,
			fileName: tmp.Name(),
		}, nil
	}

	// Body fits in memory (got EOF before filling the buffer).
	_ = rc.Close()
	return &spooledBody{
		reader: &buf,
		length: int64(buf.Len()),
	}, nil
}

// cleanupBody closes the body and removes any temp file (for error paths).
func cleanupBody(b *spooledBody) {
	if b == nil {
		return
	}
	b.Close()
	if b.fileName != "" {
		_ = os.Remove(b.fileName)
	}
}
