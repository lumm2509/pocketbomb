package core

import (
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func newTestNotifyWatcherState(t *testing.T) *notifyWatcherState {
	t.Helper()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}

	if err := watcher.Add(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	state := &notifyWatcherState{watcher: watcher}

	// simulate the watcher reader goroutine
	state.readerDone.Add(1)
	go func() {
		defer state.readerDone.Done()
		for {
			select {
			case _, ok := <-watcher.Events:
				if !ok {
					return
				}
			case _, ok := <-watcher.Errors:
				if !ok {
					return
				}
			}
		}
	}()

	return state
}

func TestNotifyWatcherStateStopWaitsInflightCallback(t *testing.T) {
	t.Parallel()

	state := newTestNotifyWatcherState(t)

	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})

	state.scheduleReload(0, func() {
		close(started)
		<-release
		close(finished)
	})
	<-started

	stopped := make(chan struct{})
	go func() {
		state.stop(true)
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("Expected stop(true) to wait for the in-flight callback")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop(true) didn't return after the callback completion")
	}

	select {
	case <-finished:
	default:
		t.Fatal("Expected the in-flight callback to be completed before stop(true) returns")
	}
}

func TestNotifyWatcherStateStopWithoutWaiting(t *testing.T) {
	t.Parallel()

	state := newTestNotifyWatcherState(t)

	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	// e.g. a reload callback blocked on the db writer held by the ClearBootstrap caller
	state.scheduleReload(0, func() {
		close(started)
		<-release
	})
	<-started

	stopped := make(chan struct{})
	go func() {
		state.stop(false)
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Expected stop(false) to not wait for the in-flight callback (deadlock)")
	}
}

func TestNotifyWatcherStateNoCallbacksAfterStop(t *testing.T) {
	t.Parallel()

	state := newTestNotifyWatcherState(t)

	calls := make(chan struct{}, 10)

	// pending (not yet fired) callback
	state.scheduleReload(30*time.Millisecond, func() { calls <- struct{}{} })

	state.stop(true)

	// scheduled after stop
	state.scheduleReload(0, func() { calls <- struct{}{} })

	time.Sleep(100 * time.Millisecond)

	if len(calls) != 0 {
		t.Fatalf("Expected no callbacks after stop, got %d", len(calls))
	}

	// stop is idempotent
	state.stop(true)
	state.stop(false)
}
