package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/security"
	"github.com/pocketbase/dbx"
)

const systemHookIdNotifyWatcher = "__pbNotifyWatcherSystemHook__"

// The OnBootstrapClear priorities of the system background services.
//
// They must run before the logger flush handler (priority -999, see [BaseApp.initLogger])
// so that the logs produced while stopping them (e.g. a webhooks dispatcher stop timeout
// or a failed queued webhook event) are still persisted, and before the cron
// stop (999) and the databases close (the final trigger func).
//
// The notify watcher is stopped first so that no settings/collections reload
// runs while the other services are stopping.
const (
	bootstrapClearPriorityNotifyWatcher = -1003
	bootstrapClearPriorityLLMLogs       = -1002
	bootstrapClearPriorityWebhooks      = -1001
	bootstrapClearPriorityLoggerFlush   = -999
)

// notifyWatcherState wraps the fsnotify watcher and its debounce timer
// so that the background goroutine and any in-flight debounce callback
// are fully stopped before the app databases are closed on ClearBootstrap.
type notifyWatcherState struct {
	watcher *fsnotify.Watcher

	timerMu sync.Mutex
	timer   *time.Timer

	// cbMu is held for the whole duration of a debounce callback
	cbMu    sync.Mutex
	stopped atomic.Bool

	readerDone sync.WaitGroup
	stopOnce   sync.Once
}

// stop stops the watcher and its debounce timer.
//
// If waitInflight is set, it also waits for the watcher goroutine and
// for the in-flight debounce callback (if any) to complete.
//
// Note that waitInflight must be false when stop is called while the caller
// holds the data db writer (e.g. inside a transaction) because the in-flight
// callback could be blocked on it (aka. deadlock).
func (s *notifyWatcherState) stop(waitInflight bool) {
	s.stopOnce.Do(func() {
		s.timerMu.Lock()
		if s.timer != nil {
			s.timer.Stop()
			s.timer = nil
		}
		s.timerMu.Unlock()

		// the callbacks that haven't started yet become no-op
		s.stopped.Store(true)

		_ = s.watcher.Close()

		if waitInflight {
			s.readerDone.Wait()

			// wait for the in-flight callback (if any)
			s.cbMu.Lock()
			s.cbMu.Unlock()
		}
	})
}

func (s *notifyWatcherState) scheduleReload(delay time.Duration, fn func()) {
	s.timerMu.Lock()
	defer s.timerMu.Unlock()

	if s.stopped.Load() {
		return
	}

	if s.timer != nil {
		s.timer.Stop()
	}

	s.timer = time.AfterFunc(delay, func() {
		s.cbMu.Lock()
		defer s.cbMu.Unlock()

		if s.stopped.Load() {
			return
		}

		fn()
	})
}

func (app *BaseApp) registerNotifyWatcherHooks() {
	var notifyWatcher *notifyWatcherState

	instanceId := "@" + security.PseudorandomString(10)

	localNotifyDirPath := filepath.Join(app.DataDir(), LocalNotifyDirName)
	settingsFile := filepath.Join(localNotifyDirPath, "settings"+instanceId)
	collectionsFile := filepath.Join(localNotifyDirPath, "collections"+instanceId)

	// init
	app.OnBootstrap().Bind(&hook.Handler[*BootstrapEvent]{
		Id: systemHookIdNotifyWatcher,
		Func: func(e *BootstrapEvent) error {
			err := e.Next()
			if err != nil {
				return err
			}

			if notifyWatcher != nil {
				notifyWatcher.stop(true)
			}

			notifyWatcher, err = createNotifyDirWatcher(e.App, instanceId, localNotifyDirPath)
			if err != nil {
				e.App.Logger().Warn("Notify dir watcher failure.", "error", err)
			}

			return nil
		},
		Priority: -998,
	})

	// cleanup
	app.OnTerminate().Bind(&hook.Handler[*TerminateEvent]{
		Id: systemHookIdNotifyWatcher,
		Func: func(e *TerminateEvent) error {
			if notifyWatcher != nil {
				notifyWatcher.stop(true)
			}

			_ = os.Remove(settingsFile)
			_ = os.Remove(collectionsFile)

			return e.Next()
		},
		Priority: -998,
	})

	// stop before the app databases are closed
	// (and before the other bootstrap clear handlers, see bootstrapClearPriorityNotifyWatcher)
	app.OnBootstrapClear().Bind(&hook.Handler[*BootstrapEvent]{
		Id: systemHookIdNotifyWatcher,
		Func: func(e *BootstrapEvent) error {
			if notifyWatcher != nil {
				// extra precaution in case the hook was manually triggered while inside a db transaction
				// (the in-flight reload callback could be waiting for the db writer)
				_, isTx := e.App.NonconcurrentDB().(*dbx.Tx)
				notifyWatcher.stop(!isTx)
			}

			return e.Next()
		},
		Priority: bootstrapClearPriorityNotifyWatcher,
	})

	// ---------------------------------------------------------------

	settingsNotify := func(e *ModelEvent) error {
		err := e.Next()
		if err != nil || e.Model.PK() != paramsKeySettings {
			return err
		}

		if notifyWatcher != nil {
			if err := os.WriteFile(settingsFile, nil, 0644); err != nil {
				e.App.Logger().Warn("Failed to write watcher file", "error", err, "file", settingsFile)
			}
			_ = os.Remove(settingsFile)
		}

		return nil
	}
	app.OnModelAfterCreateSuccess(paramsTable).Bind(&hook.Handler[*ModelEvent]{
		Id:       systemHookIdNotifyWatcher,
		Func:     settingsNotify,
		Priority: 999,
	})
	app.OnModelAfterUpdateSuccess(paramsTable).Bind(&hook.Handler[*ModelEvent]{
		Id:       systemHookIdNotifyWatcher,
		Func:     settingsNotify,
		Priority: 999,
	})

	// ---------------------------------------------------------------

	collectionsNotify := func(e *CollectionEvent) error {
		if err := e.Next(); err != nil {
			return err
		}

		if notifyWatcher != nil {
			if err := os.WriteFile(collectionsFile, nil, 0644); err != nil {
				e.App.Logger().Warn("Failed to write watcher file", "error", err, "file", collectionsFile)
			}
			_ = os.Remove(collectionsFile)
		}

		return nil
	}
	app.OnCollectionAfterCreateSuccess().Bind(&hook.Handler[*CollectionEvent]{
		Id:       systemHookIdNotifyWatcher,
		Func:     collectionsNotify,
		Priority: 999,
	})
	app.OnCollectionAfterUpdateSuccess().Bind(&hook.Handler[*CollectionEvent]{
		Id:       systemHookIdNotifyWatcher,
		Func:     collectionsNotify,
		Priority: 999,
	})
	app.OnCollectionAfterDeleteSuccess().Bind(&hook.Handler[*CollectionEvent]{
		Id:       systemHookIdNotifyWatcher,
		Func:     collectionsNotify,
		Priority: 999,
	})
}

func createNotifyDirWatcher(app App, instanceId string, localNotifyDirPath string) (*notifyWatcherState, error) {
	// create the notify dir (if not already)
	err := os.MkdirAll(localNotifyDirPath, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create a notify dir: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to init notify dir watcher: %w", err)
	}

	err = watcher.Add(localNotifyDirPath)
	if err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("unable to watch notify dir: %w", err)
	}

	state := &notifyWatcherState{watcher: watcher}

	// watch
	state.readerDone.Add(1)
	routine.FireAndForget(func() {
		defer state.readerDone.Done()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// modified from within the current app instance or cleanup event
				if strings.HasSuffix(event.Name, instanceId) || event.Has(fsnotify.Remove) || !app.IsBootstrapped() {
					continue
				}

				state.scheduleReload(50*time.Millisecond, func() {
					filename := filepath.Base(event.Name)

					// settings changed
					if strings.HasPrefix(filename, "settings@") {
						app.Logger().Debug("Reloading settings after notify event")

						err := app.ReloadSettings()
						if err != nil {
							app.Logger().Warn("Failed to reload app settings after notify", "error", err)
						}
						return
					}

					// collections changed
					if strings.HasPrefix(filename, "collections@") {
						app.Logger().Debug("Reloading cached collections after notify event")

						err := app.ReloadCachedCollections()
						if err != nil {
							app.Logger().Warn("Failed to reload cached collections after notify", "error", err)
						}
						return
					}
				})
			case err, ok := <-watcher.Errors:
				if app.IsDev() && err != nil {
					color.Red("Notify dir watch error:", err)
				}

				if !ok {
					return
				}
			}
		}
	})

	return state, nil
}
