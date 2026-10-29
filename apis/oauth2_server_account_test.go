package apis_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/mails"
	"github.com/lumm2509/pocketbomb/tests"
)

func waitForMails(t testing.TB, app *tests.TestApp, total int) {
	t.Helper()

	for i := 0; i < 100; i++ {
		if app.TestMailer.TotalSend() >= total {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("Expected %d sent mails, got %d", total, app.TestMailer.TotalSend())
}

func TestOAuth2ServerAccountMailLinks(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// new collections defaults
	c := core.NewAuthCollection("test")
	for name, body := range map[string]string{
		"/verify-email?token=":           c.VerificationTemplate.Body,
		"/password-reset/confirm?token=": c.ResetPasswordTemplate.Body,
		"/email-change/confirm?token=":   c.ConfirmEmailChangeTemplate.Body,
	} {
		if !strings.Contains(body, core.EmailPlaceholderIssuerURL+name+core.EmailPlaceholderToken) {
			t.Fatalf("Expected the default template to link to the issuer %q page, got\n%s", name, body)
		}
	}

	// resolved issuer placeholder
	user := oauth2FindRecord(t, app, "users", "test@example.com")
	user.Collection().VerificationTemplate.Body = `<a href="{ISSUER_URL}/verify-email?token={TOKEN}">verify</a>`
	if err := mails.SendRecordVerification(app, user); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(app.TestMailer.LastMessage().HTML, `href="http://localhost:8090/oauth2/users/verify-email?token=`) {
		t.Fatalf("Expected resolved issuer link, got\n%s", app.TestMailer.LastMessage().HTML)
	}
}

func TestOAuth2ServerPasswordResetPages(t *testing.T) {
	t.Parallel()

	t.Run("request", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		// the fixture template is customized -> use the default one
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			c.ResetPasswordTemplate = core.NewAuthCollection("default").ResetPasswordTemplate
		})

		b := newOAuth2Browser(t, app)

		res, body := b.get("/oauth2/nologin/password-reset")
		b.expectStatus(res, body, http.StatusNotFound)

		handle := b.startLogin("users", "app", nil)
		res, body = b.get(hrefLink(b.lastHTML, "/password-reset?"))
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, "/oauth2/users/login?auth_state="+url.QueryEscape(handle)) {
			t.Fatalf("Expected back to login link:\n%s", body)
		}
		page := body

		// csrf is required
		res, _ = b.post("/oauth2/users/password-reset", oauth2URLValues(map[string]string{"email": "test@example.com"}))
		b.expectStatus(res, "", http.StatusBadRequest)

		b.lastHTML = page
		res, body = b.submit("/oauth2/users/password-reset", map[string]string{"email": "invalid"})
		b.expectStatus(res, body, http.StatusBadRequest)

		b.lastHTML = page
		res, missingBody := b.submit("/oauth2/users/password-reset", map[string]string{"email": "missing@example.com"})
		b.expectStatus(res, missingBody, http.StatusOK)

		b.lastHTML = page
		res, existingBody := b.submit("/oauth2/users/password-reset", map[string]string{"email": "test@example.com"})
		b.expectStatus(res, existingBody, http.StatusOK)

		for _, body := range []string{missingBody, existingBody} {
			if !strings.Contains(body, "If an account with the provided email exists") {
				t.Fatalf("Expected the enumeration safe notice:\n%s", body)
			}
		}

		waitForMails(t, app, 1)
		msg := app.TestMailer.LastMessage()
		if msg.To[0].Address != "test@example.com" || !strings.Contains(msg.HTML, "http://localhost:8090/oauth2/users/password-reset/confirm?token=") {
			t.Fatalf("Unexpected password reset mail %v\n%s", msg.To, msg.HTML)
		}
		if app.TestMailer.TotalSend() != 1 {
			t.Fatalf("Expected only 1 mail, got %d", app.TestMailer.TotalSend())
		}
	})

	t.Run("confirm", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		_, session := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid"})

		token, err := user.NewPasswordResetToken()
		if err != nil {
			t.Fatal(err)
		}

		clientsUser := oauth2FindRecord(t, app, "clients", "test@example.com")
		otherToken, _ := clientsUser.NewPasswordResetToken()
		verificationToken, _ := user.NewVerificationToken()

		b := newOAuth2Browser(t, app)

		for name, invalid := range map[string]string{
			"missing":            "",
			"invalid":            "invalid",
			"another collection": otherToken,
			"another token type": verificationToken,
		} {
			res, body := b.get("/oauth2/users/password-reset/confirm?token=" + url.QueryEscape(invalid))
			if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "The link is invalid or has expired.") {
				t.Fatalf("[%s] Expected invalid link page, got %d", name, res.StatusCode)
			}
		}

		res, body := b.get("/oauth2/users/password-reset/confirm?token=" + url.QueryEscape(token))
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, user.Email()) || hiddenField(body, "token") != token {
			t.Fatalf("Expected the confirm form:\n%s", body)
		}
		page := body

		res, body = b.submit("/oauth2/users/password-reset/confirm", map[string]string{"password": "new_password_123", "passwordConfirm": "other"})
		b.expectStatus(res, body, http.StatusBadRequest)

		b.lastHTML = page
		res, body = b.submit("/oauth2/users/password-reset/confirm", map[string]string{"password": "1", "passwordConfirm": "1"})
		b.expectStatus(res, body, http.StatusBadRequest)

		b.lastHTML = page
		res, body = b.submit("/oauth2/users/password-reset/confirm", map[string]string{"password": "new_password_123", "passwordConfirm": "new_password_123"})
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, "Password changed") {
			t.Fatalf("Expected success page:\n%s", body)
		}

		fresh := oauth2FindRecord(t, app, "users", "test@example.com")
		if !fresh.ValidatePassword("new_password_123") || !fresh.Verified() {
			t.Fatal("Expected the new password and verified upgrade")
		}

		// the password change ended the record sessions
		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected ended session after password reset, got %q", s.Status())
		}

		// the token is no longer valid (tokenKey change)
		b.lastHTML = page
		res, _ = b.submit("/oauth2/users/password-reset/confirm", map[string]string{"password": "another_123456", "passwordConfirm": "another_123456"})
		b.expectStatus(res, "", http.StatusBadRequest)
	})
}

func TestOAuth2ServerVerifyEmailPage(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")
	token, err := user.NewVerificationToken()
	if err != nil {
		t.Fatal(err)
	}

	superuser := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
	superuserToken, _ := superuser.NewVerificationToken()

	b := newOAuth2Browser(t, app)

	res, _ := b.get("/oauth2/_superusers/verify-email?token=" + url.QueryEscape(superuserToken))
	b.expectStatus(res, "", http.StatusBadRequest)

	res, body := b.get("/oauth2/users/verify-email?token=" + url.QueryEscape(token))
	b.expectStatus(res, body, http.StatusOK)

	// GET doesn't verify (e.g. mail link scanners)
	if oauth2FindRecord(t, app, "users", "test@example.com").Verified() {
		t.Fatal("Expected the record to remain unverified on GET")
	}

	// csrf is required
	res, _ = b.post("/oauth2/users/verify-email", oauth2URLValues(map[string]string{"token": token}))
	b.expectStatus(res, "", http.StatusBadRequest)

	b.lastHTML = body
	res, body = b.submit("/oauth2/users/verify-email", nil)
	b.expectStatus(res, body, http.StatusOK)
	if !strings.Contains(body, "Your email address has been verified.") {
		t.Fatalf("Expected verified page:\n%s", body)
	}

	if !oauth2FindRecord(t, app, "users", "test@example.com").Verified() {
		t.Fatal("Expected the record to be verified")
	}

	// already verified record
	verifiedUser := oauth2FindRecord(t, app, "users", "test2@example.com")
	verifiedToken, _ := verifiedUser.NewVerificationToken()
	res, body = b.get("/oauth2/users/verify-email?token=" + url.QueryEscape(verifiedToken))
	b.expectStatus(res, body, http.StatusOK)
	if !strings.Contains(body, "already verified") {
		t.Fatalf("Expected already verified page:\n%s", body)
	}
}

func TestOAuth2ServerEmailChangePage(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	user := oauth2FindRecord(t, app, "users", "test@example.com")

	token, err := user.NewEmailChangeToken("changed@example.com")
	if err != nil {
		t.Fatal(err)
	}
	takenToken, _ := user.NewEmailChangeToken("test2@example.com")

	superuser := oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
	superuserToken, _ := superuser.NewEmailChangeToken("changed@example.com")

	b := newOAuth2Browser(t, app)

	for name, invalid := range map[string]string{
		"invalid":   "invalid",
		"taken":     takenToken,
		"superuser": superuserToken,
	} {
		collection := "users"
		if name == "superuser" {
			collection = core.CollectionNameSuperusers
		}
		res, _ := b.get("/oauth2/" + collection + "/email-change/confirm?token=" + url.QueryEscape(invalid))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("[%s] Expected 400, got %d", name, res.StatusCode)
		}
	}

	res, body := b.get("/oauth2/users/email-change/confirm?token=" + url.QueryEscape(token))
	b.expectStatus(res, body, http.StatusOK)
	if !strings.Contains(body, "changed@example.com") {
		t.Fatalf("Expected the new email in the confirm page:\n%s", body)
	}
	page := body

	res, body = b.submit("/oauth2/users/email-change/confirm", map[string]string{"password": "wrong"})
	b.expectStatus(res, body, http.StatusBadRequest)
	if !strings.Contains(body, "Invalid password.") {
		t.Fatalf("Expected invalid password error:\n%s", body)
	}

	b.lastHTML = page
	res, body = b.submit("/oauth2/users/email-change/confirm", map[string]string{"password": "1234567890"})
	b.expectStatus(res, body, http.StatusOK)

	changed, err := app.FindAuthRecordByEmail("users", "changed@example.com")
	if err != nil || changed.Id != user.Id || !changed.Verified() {
		t.Fatalf("Expected the email to be changed and verified, got %v", err)
	}
}

func TestOAuth2ServerAccountPagesHooks(t *testing.T) {
	t.Parallel()

	t.Run("password reset request and confirm", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		calls := []string{}
		app.OnRecordRequestPasswordResetRequest("users").BindFunc(func(e *core.RecordRequestPasswordResetRequestEvent) error {
			calls = append(calls, "request:"+e.Record.Email())
			return e.Next()
		})
		app.OnRecordConfirmPasswordResetRequest("users").BindFunc(func(e *core.RecordConfirmPasswordResetRequestEvent) error {
			calls = append(calls, "confirm:"+e.Record.Email())
			return e.Next()
		})

		b := newOAuth2Browser(t, app)
		b.get("/oauth2/users/password-reset")
		res, body := b.submit("/oauth2/users/password-reset", map[string]string{"email": "test@example.com"})
		b.expectStatus(res, body, http.StatusOK)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		token, _ := user.NewPasswordResetToken()
		b.get("/oauth2/users/password-reset/confirm?token=" + url.QueryEscape(token))
		res, body = b.submit("/oauth2/users/password-reset/confirm", map[string]string{"password": "new_password_123", "passwordConfirm": "new_password_123"})
		b.expectStatus(res, body, http.StatusOK)

		if strings.Join(calls, ",") != "request:test@example.com,confirm:test@example.com" {
			t.Fatalf("Unexpected hook calls %v", calls)
		}
	})

	t.Run("confirm hooks could reject", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		app.OnRecordConfirmPasswordResetRequest().BindFunc(func(e *core.RecordConfirmPasswordResetRequestEvent) error {
			return e.BadRequestError("Password reset is disabled.", nil)
		})
		app.OnRecordConfirmVerificationRequest().BindFunc(func(e *core.RecordConfirmVerificationRequestEvent) error {
			return e.BadRequestError("Verification is disabled.", nil)
		})
		app.OnRecordConfirmEmailChangeRequest().BindFunc(func(e *core.RecordConfirmEmailChangeRequestEvent) error {
			if e.NewEmail != "changed@example.com" {
				t.Errorf("Expected the event new email, got %q", e.NewEmail)
			}
			return e.BadRequestError("Email change is disabled.", nil)
		})

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		b := newOAuth2Browser(t, app)

		resetToken, _ := user.NewPasswordResetToken()
		b.get("/oauth2/users/password-reset/confirm?token=" + url.QueryEscape(resetToken))
		res, body := b.submit("/oauth2/users/password-reset/confirm", map[string]string{"password": "new_password_123", "passwordConfirm": "new_password_123"})
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Password reset is disabled.") {
			t.Fatalf("Expected rejected password reset, got %d", res.StatusCode)
		}
		if oauth2FindRecord(t, app, "users", "test@example.com").ValidatePassword("new_password_123") {
			t.Fatal("Expected the password to remain unchanged")
		}

		verificationToken, _ := user.NewVerificationToken()
		b.get("/oauth2/users/verify-email?token=" + url.QueryEscape(verificationToken))
		res, body = b.submit("/oauth2/users/verify-email", nil)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Verification is disabled.") {
			t.Fatalf("Expected rejected verification, got %d", res.StatusCode)
		}
		if oauth2FindRecord(t, app, "users", "test@example.com").Verified() {
			t.Fatal("Expected the record to remain unverified")
		}

		changeToken, _ := user.NewEmailChangeToken("changed@example.com")
		b.get("/oauth2/users/email-change/confirm?token=" + url.QueryEscape(changeToken))
		res, body = b.submit("/oauth2/users/email-change/confirm", map[string]string{"password": "1234567890"})
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Email change is disabled.") {
			t.Fatalf("Expected rejected email change, got %d", res.StatusCode)
		}
		if _, err := app.FindAuthRecordByEmail("users", "changed@example.com"); err == nil {
			t.Fatal("Expected the email to remain unchanged")
		}
	})
}

func TestOAuth2ServerVerifyEmailRequestPage(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	var hookCalls int
	app.OnRecordRequestVerificationRequest("users").BindFunc(func(e *core.RecordRequestVerificationRequestEvent) error {
		hookCalls++
		return e.Next()
	})

	b := newOAuth2Browser(t, app)

	res, body := b.get("/oauth2/_superusers/verify-email/request")
	b.expectStatus(res, body, http.StatusNotFound)

	res, page := b.get("/oauth2/users/verify-email/request")
	b.expectStatus(res, page, http.StatusOK)

	// csrf is required
	res, _ = b.post("/oauth2/users/verify-email/request", oauth2URLValues(map[string]string{"email": "test@example.com"}))
	b.expectStatus(res, "", http.StatusBadRequest)

	b.lastHTML = page
	res, body = b.submit("/oauth2/users/verify-email/request", map[string]string{"email": "invalid"})
	b.expectStatus(res, body, http.StatusBadRequest)

	responses := []string{}
	for _, email := range []string{"missing@example.com", "test2@example.com", "test@example.com"} {
		b.lastHTML = page
		res, body = b.submit("/oauth2/users/verify-email/request", map[string]string{"email": email})
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, "If an unverified account with the provided email exists") {
			t.Fatalf("[%s] Expected the enumeration safe notice", email)
		}
		responses = append(responses, regexpReplaceVariable(strings.ReplaceAll(body, email, "")))
	}

	if responses[0] != responses[1] || responses[1] != responses[2] {
		t.Fatal("Expected identical responses for missing, verified and unverified accounts")
	}

	waitForMails(t, app, 1)
	if app.TestMailer.TotalSend() != 1 || !strings.Contains(app.TestMailer.LastMessage().HTML, "/oauth2/users/verify-email?token=") {
		t.Fatalf("Expected a single verification email, got %d", app.TestMailer.TotalSend())
	}

	// the hook is triggered only for the existing records
	if hookCalls != 2 {
		t.Fatalf("Expected 2 hook calls, got %d", hookCalls)
	}
}

func TestOAuth2AttackAccountEnumeration(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)
	oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) { c.OTP.Enabled = true })

	normalize := func(body string) string {
		// strip the per-render values (csrf, auth_state, CSP nonce, email echo)
		for _, name := range []string{"csrf", "auth_state"} {
			if v := hiddenField(body, name); v != "" {
				body = strings.ReplaceAll(body, v, "")
			}
		}
		body = nonceRegex.ReplaceAllString(body, "")
		body = strings.ReplaceAll(body, "missing@example.com", "EMAIL")
		body = strings.ReplaceAll(body, "test2@example.com", "EMAIL")
		return body
	}

	type result struct {
		status int
		body   string
	}

	run := func(identity string, path string, values map[string]string) result {
		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		if path == "/oauth2/users/password-reset" {
			b.get("/oauth2/users/password-reset")
		}
		res, body := b.submit(path, values)
		return result{res.StatusCode, normalize(body)}
	}

	for _, c := range []struct {
		name string
		path string
		data func(email string) map[string]string
	}{
		{"password login", "/oauth2/users/login/password", func(email string) map[string]string {
			return map[string]string{"identity": email, "password": "wrong_password"}
		}},
		{"otp request", "/oauth2/users/login/otp", func(email string) map[string]string {
			return map[string]string{"email": email}
		}},
		{"password reset", "/oauth2/users/password-reset", func(email string) map[string]string {
			return map[string]string{"email": email}
		}},
	} {
		existing := run("test2@example.com", c.path, c.data("test2@example.com"))
		missing := run("missing@example.com", c.path, c.data("missing@example.com"))

		if existing.status != missing.status || existing.body != missing.body {
			t.Fatalf("%s: the responses for existing and missing accounts differ (%d vs %d)", c.name, existing.status, missing.status)
		}
	}
}

func TestOAuth2AttackSignupFieldInjection(t *testing.T) {
	t.Parallel()

	app := oauth2AttackApp(t)

	role, err := tests.CreateRole(app, "escalated", core.Permissions{System: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)
	b.get(hrefLink(b.lastHTML, "/signup"))

	res, body := b.submit("/oauth2/users/signup", map[string]string{
		"email":           "new_signup@example.com",
		"password":        "1234567890",
		"passwordConfirm": "1234567890",
		// injection attempts
		"verified":        "true",
		"tokenKey":        "attacker_known_token_key_0123456789_0123456789",
		"emailVisibility": "true",
		"roles":           role.Id,
		"role":            role.Id,
		"id":              "attackerchosen1",
		"name":            "injected",
	})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("Expected signup redirect, got %d %s", res.StatusCode, body)
	}

	record := oauth2FindRecord(t, app, "users", "new_signup@example.com")
	if record.Verified() {
		t.Fatal("Expected the new record to be unverified")
	}
	if record.TokenKey() == "attacker_known_token_key_0123456789_0123456789" {
		t.Fatal("Expected the tokenKey not to be settable")
	}
	if record.Id == "attackerchosen1" || record.GetString("name") == "injected" || record.GetBool("emailVisibility") {
		t.Fatal("Expected the extra fields to be ignored")
	}

	assignments, err := app.FindAllRoleAssignmentsByRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(assignments) != 0 {
		t.Fatalf("Expected no explicit role assignments, got %d", len(assignments))
	}

	// signup is never available for the superusers issuer
	oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)
	sb := newOAuth2Browser(t, app)
	sb.startLogin(core.CollectionNameSuperusers, core.OAuth2DashboardClientId, map[string]string{"redirect_uri": oauth2TestDashboardCallback})
	res, _ = sb.submit("/oauth2/_superusers/signup", map[string]string{
		"email":           "new_su@example.com",
		"password":        "1234567890",
		"passwordConfirm": "1234567890",
	})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected superusers signup 404, got %d", res.StatusCode)
	}
	if _, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "new_su@example.com"); err == nil {
		t.Fatal("Expected no superuser to be created")
	}
}

func TestOAuth2AttackAccountTokens(t *testing.T) {
	t.Parallel()

	confirmPasswordReset := func(b *oauth2Browser, collection string, token string) *http.Response {
		b.get("/oauth2/" + collection + "/password-reset/confirm?token=" + url.QueryEscape(token))
		res, _ := b.post("/oauth2/"+collection+"/password-reset/confirm", url.Values{
			"csrf":            {b.cookies["pb_oauth2_csrf"]},
			"token":           {token},
			"password":        {"new_password_123"},
			"passwordConfirm": {"new_password_123"},
		})
		return res
	}

	t.Run("password reset token reuse", func(t *testing.T) {
		app := oauth2AttackApp(t)

		record := oauth2FindRecord(t, app, "users", "test2@example.com")
		token, err := record.NewPasswordResetToken()
		if err != nil {
			t.Fatal(err)
		}

		// an active session of the record ends with the password change
		_, session := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), record, []string{"openid"})

		b := newOAuth2Browser(t, app)
		if res := confirmPasswordReset(b, "users", token); res.StatusCode != http.StatusOK {
			t.Fatalf("Expected the first confirm to succeed, got %d", res.StatusCode)
		}

		if res := confirmPasswordReset(b, "users", token); res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected the reused token to be rejected, got %d", res.StatusCode)
		}

		if s := oauth2ReloadSession(t, app, session.Id); s.Status() != core.AuthSessionStatusEnded {
			t.Fatalf("Expected the record sessions to be ended, got %q", s.Status())
		}
	})

	t.Run("cross-collection and cross-type tokens", func(t *testing.T) {
		app := oauth2AttackApp(t)

		clientsRecord := oauth2FindRecord(t, app, "clients", "test@example.com")
		clientsToken, _ := clientsRecord.NewPasswordResetToken()

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		verificationToken, _ := user.NewVerificationToken()
		emailChangeToken, _ := user.NewEmailChangeToken("changed@example.com")
		fileToken, _ := user.NewFileToken()

		b := newOAuth2Browser(t, app)
		for name, token := range map[string]string{
			"clients token at users":        clientsToken,
			"verification as reset":         verificationToken,
			"email change as reset":         emailChangeToken,
			"file token as reset":           fileToken,
			"access token as reset":         tests.AuthToken("users", "test@example.com"),
			"reset token with wrong issuer": strings.Replace(clientsToken, ".", ".", 1),
		} {
			res := confirmPasswordReset(b, "users", token)
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d", name, res.StatusCode)
			}
		}

		// a users verification token at the clients issuer
		res, _ := b.get("/oauth2/clients/verify-email?token=" + url.QueryEscape(verificationToken))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected cross-collection verification token to be rejected, got %d", res.StatusCode)
		}

		// a reset token as email change
		resetToken, _ := user.NewPasswordResetToken()
		res, _ = b.get("/oauth2/users/email-change/confirm?token=" + url.QueryEscape(resetToken))
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected a reset token as email change token to be rejected, got %d", res.StatusCode)
		}
	})

	t.Run("email change token reuse", func(t *testing.T) {
		app := oauth2AttackApp(t)

		user := oauth2FindRecord(t, app, "users", "test2@example.com")
		token, _ := user.NewEmailChangeToken("changed@example.com")

		confirm := func(b *oauth2Browser) int {
			b.get("/oauth2/users/email-change/confirm?token=" + url.QueryEscape(token))
			res, _ := b.post("/oauth2/users/email-change/confirm", url.Values{
				"csrf":     {b.cookies["pb_oauth2_csrf"]},
				"token":    {token},
				"password": {"1234567890"},
			})
			return res.StatusCode
		}

		b := newOAuth2Browser(t, app)
		if status := confirm(b); status != http.StatusOK {
			t.Fatalf("Expected the first email change to succeed, got %d", status)
		}
		if status := confirm(b); status != http.StatusBadRequest {
			t.Fatalf("Expected the reused email change token to be rejected, got %d", status)
		}
	})
}
