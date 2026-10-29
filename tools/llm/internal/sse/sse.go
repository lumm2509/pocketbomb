// Package sse implements a minimal Server-Sent Events reader
// and a generic driver.Stream implementation on top of it.
package sse

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// MaxLineSize is the max allowed size of a single SSE line.
const MaxLineSize = 16 << 20

// Event defines a single dispatched SSE event.
type Event struct {
	ID    string
	Event string
	Data  string
}

// Reader reads SSE events from an io.Reader.
type Reader struct {
	scanner *bufio.Scanner
	current Event
	err     error
}

// NewReader creates a new SSE Reader.
func NewReader(r io.Reader) *Reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxLineSize)

	return &Reader{scanner: scanner}
}

// Next advances to the next SSE event.
// It returns false on EOF or error (see [Reader.Err]).
func (r *Reader) Next() bool {
	var (
		ev      Event
		data    strings.Builder
		hasData bool
		hasAny  bool
	)

	for r.scanner.Scan() {
		line := r.scanner.Bytes()

		// dispatch
		if len(line) == 0 {
			if !hasAny {
				continue
			}
			ev.Data = data.String()
			r.current = ev
			return true
		}

		// comment
		if line[0] == ':' {
			continue
		}

		field, value, _ := bytes.Cut(line, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))

		hasAny = true

		switch string(field) {
		case "event":
			ev.Event = string(value)
		case "data":
			if hasData {
				data.WriteByte('\n')
			}
			data.Write(value)
			hasData = true
		case "id":
			ev.ID = string(value)
		}
	}

	r.err = r.scanner.Err()

	// dispatch the last event even if there is no trailing blank line
	if r.err == nil && hasAny {
		ev.Data = data.String()
		r.current = ev
		return true
	}

	return false
}

// Event returns the current event.
func (r *Reader) Event() Event {
	return r.current
}

// Err returns the reader error (if any).
func (r *Reader) Err() error {
	return r.err
}
