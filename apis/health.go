package apis

import (
	"net/http"
	"slices"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
)

// bindHealthApi registers the health api endpoint.
func bindHealthApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	subGroup := rg.Group("/health")
	subGroup.GET("", healthCheck)
}

// healthCheck returns a 200 OK response if the server is healthy.
func healthCheck(e *core.RequestEvent) error {
	resp := struct {
		Message string         `json:"message"`
		Code    int            `json:"code"`
		Data    map[string]any `json:"data"`
	}{
		Code:    http.StatusOK,
		Message: "API is healthy.",
	}

	// @todo evaluate whether it is worth removing the extra info from the health endpoint
	// the health details are available for any staff member acting directly
	// (not for the third-party or the application extensions online tokens)
	if e.IsStaff() {
		resp.Data = make(map[string]any, 3)
		resp.Data["canBackup"] = !e.App.Store().Has(core.StoreKeyActiveBackup)
		resp.Data["realIP"] = e.RealIP()

		// loosely check if behind a reverse proxy
		// (usually used in the dashboard to remind superusers in case deployed behind reverse-proxy)
		possibleProxyHeader := ""
		headersToCheck := append(
			slices.Clone(e.App.Settings().TrustedProxy.Headers),
			// common proxy headers
			"CF-Connecting-IP", "Fly-Client-IP", "X-Forwarded-For",
		)
		for _, header := range headersToCheck {
			if e.Request.Header.Get(header) != "" {
				possibleProxyHeader = header
				break
			}
		}
		resp.Data["possibleProxyHeader"] = possibleProxyHeader
	} else {
		resp.Data = map[string]any{} // ensure that it is returned as object
	}

	return e.JSON(http.StatusOK, resp)
}
