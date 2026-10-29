package apis

import (
	"net/http"
	"slices"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/cron"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/routine"
)

// bindCronApi registers the crons api endpoint.
func bindCronApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	subGroup := rg.Group("/crons")
	subGroup.GET("", cronsList).Bind(RequirePermission(core.PermissionResourceCrons, core.PermissionLevelRead))
	subGroup.POST("/{id}", cronRun).Bind(RequirePermission(core.PermissionResourceCrons, core.PermissionLevelWrite))
}

func cronsList(e *core.RequestEvent) error {
	jobs := e.App.Cron().Jobs()

	slices.SortStableFunc(jobs, func(a, b *cron.Job) int {
		if strings.HasPrefix(a.Id(), "__pb") {
			return 1
		}
		if strings.HasPrefix(b.Id(), "__pb") {
			return -1
		}
		return strings.Compare(a.Id(), b.Id())
	})

	return e.JSON(http.StatusOK, jobs)
}

func cronRun(e *core.RequestEvent) error {
	cronId := e.Request.PathValue("id")

	var foundJob *cron.Job

	jobs := e.App.Cron().Jobs()
	for _, j := range jobs {
		if j.Id() == cronId {
			foundJob = j
			break
		}
	}

	if foundJob == nil {
		return e.NotFoundError("Missing or invalid cron job", nil)
	}

	routine.FireAndForget(func() {
		foundJob.Run()
	})

	return e.NoContent(http.StatusNoContent)
}
