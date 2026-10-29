package core

import (
	"testing"
)

func TestBootstrapClearPriorities(t *testing.T) {
	t.Parallel()

	// the background services must be stopped before the logger flush
	// (otherwise their stop logs are lost)
	ordered := []int{
		bootstrapClearPriorityNotifyWatcher,
		bootstrapClearPriorityLLMLogs,
		bootstrapClearPriorityWebhooks,
		bootstrapClearPriorityLoggerFlush,
	}

	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("Invalid bootstrap clear priorities order %v", ordered)
		}
	}
}
