package apis

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/osutils"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/ui"
	"github.com/pocketbase/dbx"
	validation "github.com/pocketbase/ozzo-validation/v4"
)

// DefaultInstallerFunc is the default PocketBase installer function.
//
// It will attempt to open a link in the browser (with a short-lived installer
// token for the systemSuperuser) to the installer UI so that users can
// create their own custom superuser record (see the /api/installer endpoints).
//
// Note that the installer token is never accepted as auth token.
//
// See https://github.com/lumm2509/pocketbomb/discussions/5814.
func DefaultInstallerFunc(app core.App, systemSuperuser *core.Record, baseURL string) error {
	if ui.DistDirFS == nil {
		color.Magenta("You can create your first superuser by running: %s superuser upsert EMAIL PASS", executablePath())
		return nil
	}

	token, err := systemSuperuser.NewInstallerToken(installerTokenDuration)
	if err != nil {
		return err
	}

	// launch url (ignore errors and always print a help text as fallback)
	url := fmt.Sprintf("%s/_/#/pbinstall/%s", strings.TrimRight(baseURL, "/"), token)
	_ = osutils.LaunchURL(url)
	color.Magenta("\n(!) Launch the URL below in the browser if it hasn't been open already to create your first superuser account:")
	color.New(color.Bold).Add(color.FgCyan).Println(url)
	color.New(color.FgHiBlack, color.Italic).Printf("(you can also create your first superuser by running: %s superuser upsert EMAIL PASS)\n\n", executablePath())

	return nil
}

// installerTokenDuration is the duration of the installer tokens.
const installerTokenDuration = 30 * time.Minute

// bindInstallerApi registers the installer endpoints that are accessible only
// with an installer token (see [core.Record.NewInstallerToken]) and only until
// the first superuser is created.
func bindInstallerApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/installer").Bind(requireInstallerToken())

	sub.POST("", installerCreateSuperuser)
	sub.POST("/backups/upload", backupUpload).Bind(BodyLimit(0))
	sub.POST("/backups/{key}/restore", backupRestore)
}

// requireInstallerToken allows the request only with a valid installer token
// in the Authorization header and only if there is no explicit superuser yet.
func requireInstallerToken() *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id: "pbRequireInstallerToken",
		Func: func(e *core.RequestEvent) error {
			token := getAuthTokenFromRequest(e)

			record, err := e.App.FindAuthRecordByToken(token, core.TokenTypeInstaller)
			if err != nil || record.Email() != core.DefaultInstallerEmail {
				return e.UnauthorizedError("Missing or invalid installer token.", err)
			}

			if !needInstallerSuperuser(e.App) {
				return e.ForbiddenError("The installer is no longer available.", nil)
			}

			return e.Next()
		},
	}
}

type installerSuperuserForm struct {
	Email           string `form:"email" json:"email"`
	Password        string `form:"password" json:"password"`
	PasswordConfirm string `form:"passwordConfirm" json:"passwordConfirm"`
}

// POST /api/installer
//
// Creates the first superuser (the system installer superuser is
// automatically deleted afterwards). The new superuser then signs in
// to the dashboard with the regular OAuth2 login.
func installerCreateSuperuser(e *core.RequestEvent) error {
	form := &installerSuperuserForm{}
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("An error occurred while loading the submitted data.", err)
	}

	if form.Password != form.PasswordConfirm {
		return e.BadRequestError("An error occurred while validating the submitted data.", validation.Errors{
			"passwordConfirm": validation.NewError("validation_values_mismatch", "Values don't match."),
		})
	}

	collection, err := e.App.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		return e.InternalServerError("", err)
	}

	superuser := core.NewRecord(collection)
	superuser.SetEmail(form.Email)
	superuser.SetPassword(form.Password)

	// the first superuser is an Owner
	err = e.App.RunInTransaction(func(txApp core.App) error {
		if err := txApp.Save(superuser); err != nil {
			return err
		}
		return txApp.AssignOwnerRole(superuser)
	})
	if err != nil {
		return e.BadRequestError("Failed to create the superuser.", err)
	}

	return e.NoContent(http.StatusNoContent)
}

func loadInstaller(
	app core.App,
	baseURL string,
	installerFunc func(app core.App, systemSuperuser *core.Record, baseURL string) error,
) error {
	if installerFunc == nil || !needInstallerSuperuser(app) {
		return nil
	}

	superuser, err := findOrCreateInstallerSuperuser(app)
	if err != nil {
		return err
	}

	return installerFunc(app, superuser, baseURL)
}

func needInstallerSuperuser(app core.App) bool {
	total, err := app.CountRecords(core.CollectionNameSuperusers, dbx.Not(dbx.HashExp{
		"email": core.DefaultInstallerEmail,
	}))

	return err == nil && total == 0
}

func findOrCreateInstallerSuperuser(app core.App) (*core.Record, error) {
	col, err := app.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		return nil, err
	}

	record, err := app.FindAuthRecordByEmail(col, core.DefaultInstallerEmail)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}

		record = core.NewRecord(col)
		record.SetEmail(core.DefaultInstallerEmail)
		record.SetRandomPassword()

		err = app.Save(record)
		if err != nil {
			return nil, err
		}
	}

	return record, nil
}

func executablePath() string {
	if osutils.IsProbablyGoRun() {
		return "go run ."
	}

	return os.Args[0]
}
