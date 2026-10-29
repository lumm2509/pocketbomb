package core

import (
	"log"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/lumm2509/pocketbomb/tools/routine"
	"github.com/lumm2509/pocketbomb/tools/types"
)

const (
	llmLogsWriterBatchSize = 100
	llmLogsWriterInterval  = 2 * time.Second
)

// llmLogsWriter is an async batched LLM logs writer.
//
// The queued logs remain "visible" (see [llmLogsWriter.snapshot]) until
// they are persisted so that the quota checks could always account for them.
type llmLogsWriter struct {
	app *BaseApp

	mu      sync.Mutex
	pending []*LLMLog
	writing [][]*LLMLog // batches that are currently being persisted
	timer   *time.Timer

	writeMu sync.Mutex // serializes the batch writes
}

func newLLMLogsWriter(app *BaseApp) *llmLogsWriter {
	return &llmLogsWriter{app: app}
}

// add queues a new log for write.
func (w *llmLogsWriter) add(l *LLMLog) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending = append(w.pending, l)

	if len(w.pending) >= llmLogsWriterBatchSize {
		if w.timer != nil {
			w.timer.Stop()
			w.timer = nil
		}
		routine.FireAndForget(func() { w.flush() })
		return
	}

	if w.timer == nil {
		w.timer = time.AfterFunc(llmLogsWriterInterval, func() { w.flush() })
	}
}

// snapshot returns a copy of all queued and not yet persisted logs.
func (w *llmLogsWriter) snapshot() []*LLMLog {
	w.mu.Lock()
	defer w.mu.Unlock()

	result := slices.Clone(w.pending)
	for _, batch := range w.writing {
		result = append(result, batch...)
	}

	return result
}

// flush persists all queued logs.
func (w *llmLogsWriter) flush() {
	w.mu.Lock()
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	batch := w.pending
	w.pending = nil
	if len(batch) > 0 {
		w.writing = append(w.writing, batch)
	}
	w.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	defer func() {
		w.mu.Lock()
		for i, b := range w.writing {
			if len(b) > 0 && len(batch) > 0 && &b[0] == &batch[0] {
				w.writing = append(w.writing[:i], w.writing[i+1:]...)
				break
			}
		}
		w.mu.Unlock()
	}()

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if !w.app.IsBootstrapped() {
		return
	}

	err := w.app.AuxRunInTransaction(func(txApp App) error {
		for _, l := range batch {
			l.MarkAsNew()
			if err := txApp.AuxSave(l); err != nil {
				log.Println("Failed to write LLM log", l.Id, err)
			}
		}

		return nil
	})
	if err != nil {
		w.app.Logger().Warn("Failed to write LLM logs", slog.String("error", err.Error()))
	}
}

// -------------------------------------------------------------------

// WriteLLMLog queues the provided LLM log for async batched write
// in the auxiliary db (it is no-op if the LLM logs are disabled).
//
// The queued logs are persisted every ~2s or when the batch size
// threshold is reached (and also before the app bootstrap state is cleared).
func (app *BaseApp) WriteLLMLog(l *LLMLog) {
	if l == nil || !app.Settings().LLM.Logs.Enabled || app.Settings().LLM.Logs.MaxDays <= 0 {
		return
	}

	if l.Id == "" {
		l.Id = GenerateDefaultRandomId()
	}

	if l.Created.IsZero() {
		l.Created = types.NowDateTime()
	}

	app.llmLogsWriter.add(l)
}

// FlushLLMLogs synchronously persists all queued LLM logs.
//
// This method is used mainly internally and in the tests.
func (app *BaseApp) FlushLLMLogs() {
	app.llmLogsWriter.flush()
}
