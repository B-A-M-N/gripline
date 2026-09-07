package proxy

import (
	"bytes"
	"io"
	"math"
	"os"
	"sync"
)

// spoolMemoryThreshold is the body size above which we spool to a temp file
// instead of keeping everything in memory. 256 KiB keeps the per-connection
// memory bounded while avoiding the temp-file overhead for typical prompts.
const spoolMemoryThreshold = 256 << 10

// spoolTempDir is the directory temp spool files are created in. Empty uses
// the OS default. A var (not const) so tests can scope leak assertions to a
// directory they control.
var spoolTempDir = ""

// spooledBody is the result of bounded body reading (P0.16). It is an
// io.ReadCloser that may be backed by memory or a temp file.
//
// Ownership: Close is the ONE teardown path. It closes the backing reader and
// removes any temp file, exactly once — the ordinary request-body lifecycle
// (http.Transport closes the request body after RoundTrip) therefore cleans up
// the temp filename without a separate error-path-only call. tooLarge bodies
// are never valid request bodies: the caller must reject them and Close them,
// never forward the (truncated) content.
type spooledBody struct {
	reader   io.Reader
	closer   io.Closer
	length   int64
	tooLarge bool
	fileName string // nonempty when backed by a temp file
	once     sync.Once
}

func (b *spooledBody) Read(p []byte) (int, error) {
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

// Close tears the spooled body down: closes the backing file (if any) and
// removes the temp filename. Idempotent; safe to call from both the transport's
// body-close and an explicit error-path cleanup.
func (b *spooledBody) Close() error {
	var result error
	b.once.Do(func() {
		if b.closer != nil {
			result = b.closer.Close()
		}
		if b.fileName != "" {
			if err := os.Remove(b.fileName); err != nil && result == nil {
				result = err
			}
		}
	})
	return result
}

// spoolBody reads the body with an absolute cap of maxBytes. Small bodies stay
// in memory; larger ones are spooled to a temp file. maxBytes is the ACTUAL
// allowed limit: the reader consumes at most maxBytes+1 bytes (overflow-safe)
// so "exactly at the limit" is distinguishable from "one byte over", and sets
// tooLarge=true when the body exceeds maxBytes. A tooLarge result never
// carries a valid forwardable body — the caller must reject (413) and Close it.
func spoolBody(rc io.ReadCloser, maxBytes int64, memThreshold int64) (*spooledBody, error) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	// readCap = maxBytes+1, clamped for maxBytes == MaxInt64.
	readCap := maxBytes + 1
	if readCap <= 0 {
		readCap = math.MaxInt64
	}
	memLimit := memThreshold
	if memLimit > readCap {
		memLimit = readCap
	}

	buf := &bytes.Buffer{}
	_, err := io.CopyN(buf, rc, memLimit)
	if err != nil && err != io.EOF {
		_ = rc.Close()
		return nil, err
	}
	if err == nil {
		// Filled memLimit without hitting EOF. Either the read cap is already
		// exhausted (body > maxBytes, nothing more may be read) or the memory
		// threshold is — spool the remainder to a temp file.
		if int64(buf.Len()) >= readCap {
			// Consumed maxBytes+1 bytes with no EOF: the body exceeds the
			// limit. Never expose the truncated content as a valid body.
			_ = rc.Close()
			return &spooledBody{reader: buf, tooLarge: true, length: int64(buf.Len())}, nil
		}
		tmp, err := os.CreateTemp(spoolTempDir, "gripline-body-*.tmp")
		if err != nil {
			_ = rc.Close()
			return nil, err
		}
		b := &spooledBody{reader: tmp, closer: tmp, fileName: tmp.Name()}
		if _, err := tmp.Write(buf.Bytes()); err != nil {
			_ = b.Close() // closes + removes the temp file
			_ = rc.Close()
			return nil, err
		}
		// Copy up to the rest of the read cap (maxBytes+1 total). CopyN
		// returns io.EOF iff the body ended FIRST — i.e. total < readCap, so
		// total <= maxBytes. err == nil means the full cap was consumed
		// without EOF: the body exceeds maxBytes.
		written, err := io.CopyN(tmp, rc, readCap-int64(buf.Len()))
		_ = rc.Close()
		if err != nil && err != io.EOF {
			_ = b.Close()
			return nil, err
		}
		b.length = int64(buf.Len()) + written
		b.tooLarge = err == nil
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			_ = b.Close()
			return nil, err
		}
		return b, nil
	}

	// EOF: the whole body is in memory (possibly still over maxBytes when the
	// read cap equals the memory limit — tooLarge is computed, not assumed).
	_ = rc.Close()
	return &spooledBody{
		reader:   buf,
		length:   int64(buf.Len()),
		tooLarge: int64(buf.Len()) > maxBytes,
	}, nil
}
