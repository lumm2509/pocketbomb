package sse

import (
	"io"
	"sync"

	"github.com/lumm2509/pocketbomb/tools/llm/driver"
)

// HandlerFunc converts a single SSE event into zero or more normalized events.
//
// Return done=true to stop the stream (e.g. on "[DONE]" or "message_stop").
type HandlerFunc func(ev Event) (events []driver.StreamEvent, done bool, err error)

var _ driver.Stream = (*Stream)(nil)

// Stream is a generic SSE based [driver.Stream] implementation.
type Stream struct {
	body    io.ReadCloser
	reader  *Reader
	handler HandlerFunc
	queue   []driver.StreamEvent
	current driver.StreamEvent
	err     error
	done    bool

	closeOnce sync.Once
	closeErr  error
}

// NewStream creates a new SSE stream from the provided response body.
func NewStream(body io.ReadCloser, handler HandlerFunc) *Stream {
	return &Stream{
		body:    body,
		reader:  NewReader(body),
		handler: handler,
	}
}

// Next implements [driver.Stream.Next].
func (s *Stream) Next() bool {
	for len(s.queue) == 0 {
		if s.done || s.err != nil {
			return false
		}

		if !s.reader.Next() {
			s.err = s.reader.Err()
			s.done = true
			return false
		}

		events, done, err := s.handler(s.reader.Event())
		s.queue = append(s.queue, events...)
		s.done = done
		s.err = err
	}

	s.current = s.queue[0]
	s.queue = s.queue[1:]

	return true
}

// Event implements [driver.Stream.Event].
func (s *Stream) Event() driver.StreamEvent {
	return s.current
}

// Err implements [driver.Stream.Err].
func (s *Stream) Err() error {
	return s.err
}

// Close implements [driver.Stream.Close].
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.done = true
		s.closeErr = s.body.Close()
	})
	return s.closeErr
}
