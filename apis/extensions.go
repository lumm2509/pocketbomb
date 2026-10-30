package apis

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/ui"
)

// bindUIExtensions binds the superuser UI extensions routes to the ServeEvent.Router.
//
// This method does nothing if the superuser UI is not bundled (aka. build with "no_ui" tag),
func bindUIExtensions(app core.App) {
	if ui.DistDirFS == nil {
		return
	}

	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Priority: 9999, // execute as latest as possible
		Func: func(se *core.ServeEvent) error {
			uiGroup := se.Router.Group("/_").
				BindFunc(func(e *core.RequestEvent) error {
					if !e.App.IsDev() && e.Response.Header().Get("Cache-Control") == "" {
						e.Response.Header().Set("Cache-Control", "max-age=1209600, stale-while-revalidate=86400")
					}

					if e.Response.Header().Get("Content-Security-Policy") == "" {
						if isUIExtensionDocument(e.Request.URL.Path) {
							e.Response.Header().Set("Content-Security-Policy", dashboardCSPWithScriptSrc(e.App, "script-src 'self'"))
						} else {
							e.Response.Header().Set("Content-Security-Policy", dashboardCSP(e.App, ""))
						}
					}

					return e.Next()
				}).
				Bind(Gzip())

			// register static extension routes
			for _, ext := range se.UIExtensions {
				if ext.Name == "" || ext.FS == nil {
					se.App.Logger().Debug("Invalid UI extension configuration", slog.Any("extension", ext))
					continue
				}

				uiGroup.GET("/extensions/"+ext.Name+"/{path...}", Static(ext.FS, false))
			}

			// combine all extensions main.js in one file
			//
			// note: don't cache in memory to allow previewing changes without restart
			uiGroup.GET("/extensions.js", func(re *core.RequestEvent) error {
				buf := new(bytes.Buffer)

				for _, ext := range se.UIExtensions {
					err := copyExtensionMainjs(buf, ext)
					if err != nil {
						return re.InternalServerError("An error occurred while generating the main.js extension file", err)
					}
				}

				return re.Stream(200, "text/javascript", buf)
			}).Bind(SkipSuccessActivityLog())

			return se.Next()
		},
	})
}

// isUIExtensionDocument reports whether the provided path is an HTML document of an UI extension
// (installed by the Owner; its own scripts run like in upstream, only in these documents).
func isUIExtensionDocument(urlPath string) bool {
	rest, ok := strings.CutPrefix(urlPath, "/_/extensions/")
	if !ok {
		return false
	}

	ext := strings.ToLower(path.Ext(rest))

	return ext == "" || ext == ".html" || ext == ".htm"
}

func copyExtensionMainjs(buf *bytes.Buffer, ext core.UIExtension) error {
	f, err := ext.FS.Open("main.js")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to copy
		}

		return fmt.Errorf("[UI extension %q] main.js open error: %w", ext.Name, err)
	}
	defer f.Close()

	// wrap in a self-executing function to avoid scope and concatenation issues
	// (the await/async is for top-level await)
	_, _ = buf.WriteString("await (async function(){")

	_, err = io.Copy(buf, f)
	if err != nil {
		return fmt.Errorf("[UI extension %q] main.js copy error: %w", ext.Name, err)
	}

	_, _ = buf.WriteString("})();")

	return nil
}
