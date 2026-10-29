// Package pages contains the server-rendered hosted pages
// (e.g. the OAuth2 server login, consent and account pages).
//
// The pages are plain HTML forms without JavaScript and they are rendered
// with a strict nonce based Content-Security-Policy.
package pages

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/security"
)

//go:embed layout.html style.css oauth2/*.html
var pagesFS embed.FS

// templates holds the parsed page templates by their name (e.g. "oauth2/login").
var templates = func() map[string]*template.Template {
	layout := template.Must(template.ParseFS(pagesFS, "layout.html"))

	result := map[string]*template.Template{}

	files, err := fs.Glob(pagesFS, "oauth2/*.html")
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		name := strings.TrimSuffix(file, ".html")
		result[name] = template.Must(template.Must(layout.Clone()).ParseFS(pagesFS, file))
	}

	return result
}()

var css = func() template.CSS {
	raw, err := pagesFS.ReadFile("style.css")
	if err != nil {
		panic(err)
	}
	return template.CSS(raw)
}()

var hexColorRegex = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}){1,2}$`)

// DefaultPrimaryColor is the pages accent color fallback.
const DefaultPrimaryColor = "#16161a"

// Branding defines the hosted pages branding data.
type Branding struct {
	Title        string
	LogoURL      string
	PrimaryColor template.CSS
}

// NewBranding returns the hosted pages branding of the provided auth collection
// (with fallback to the app name and accent color).
func NewBranding(app core.App, collection *core.Collection) Branding {
	loginPage := collection.OAuth2Server.LoginPage

	result := Branding{
		Title:   loginPage.Title,
		LogoURL: loginPage.LogoURL,
	}

	if result.Title == "" {
		result.Title = app.Settings().Meta.AppName
	}

	color := loginPage.PrimaryColor
	if !hexColorRegex.MatchString(color) {
		color = app.Settings().Meta.AccentColor
	}
	if !hexColorRegex.MatchString(color) {
		color = DefaultPrimaryColor
	}
	result.PrimaryColor = template.CSS(color)

	return result
}

// Data defines the template data of a single page render.
type Data struct {
	Branding

	// Nonce is the CSP nonce of the current render.
	Nonce string

	// CSS is the inlined pages stylesheet.
	CSS template.CSS

	// Page is the page specific view data (see the *Page structs).
	Page any
}

// Render renders the specified page (e.g. "oauth2/login") into w
// with a strict nonce based Content-Security-Policy and no-store cache headers.
func Render(w http.ResponseWriter, status int, name string, branding Branding, page any) error {
	tmpl, ok := templates[name]
	if !ok {
		return errors.New("unknown page " + name)
	}

	data := &Data{
		Branding: branding,
		Nonce:    security.RandomString(24),
		CSS:      css,
		Page:     page,
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		return err
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", ContentSecurityPolicy(data.Nonce))
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")

	w.WriteHeader(status)

	_, err := w.Write(buf.Bytes())

	return err
}

// ContentSecurityPolicy returns the hosted pages Content-Security-Policy for the provided nonce.
//
// Note that scripts are not allowed at all and that "form-action" is
// intentionally not set because some browsers apply it also to the
// redirects after the form submission (e.g. back to the client redirect_uri).
func ContentSecurityPolicy(nonce string) string {
	return strings.Join([]string{
		"default-src 'none'",
		"script-src 'none'",
		"style-src 'nonce-" + nonce + "'",
		"img-src 'self' https: data:",
		"base-uri 'none'",
		"frame-ancestors 'none'",
	}, "; ")
}
