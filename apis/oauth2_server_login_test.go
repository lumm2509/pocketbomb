package apis_test

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/security"

	"github.com/lumm2509/pocketbomb/apis"
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tests"
	"github.com/lumm2509/pocketbomb/tools/types"
)

func oauth2EnableMFA(rule string) func(c *core.Collection) {
	return func(c *core.Collection) {
		c.MFA.Enabled = true
		c.MFA.Rule = rule
		c.MFA.Duration = 600
		c.PasswordAuth.Enabled = true
		c.OTP.Enabled = true
	}
}

func TestOAuth2ServerMFA(t *testing.T) {
	t.Parallel()

	t.Run("password + otp", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA(""))

		user := oauth2FindRecord(t, app, "users", "test2@example.com")

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", map[string]string{"auth_state": handle})

		session := b.sessionByHandle(handle)
		if session.Status() != core.AuthSessionStatusPending || session.RecordRef() != user.Id || !session.MFARequired() {
			t.Fatalf("Expected pending identified session with required MFA, got %q %q %v", session.Status(), session.RecordRef(), session.MFARequired())
		}
		if _, ok := b.cookies["pb_session"]; ok {
			t.Fatal("Expected no SSO session before MFA completion")
		}

		// the login page of a partially authenticated flow redirects to the MFA page
		res, _ = b.get("/oauth2/users/login?auth_state=" + handle)
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)

		res, body := b.follow(res)
		b.expectStatus(res, body, http.StatusOK)

		// the already used method is not offered again
		if strings.Contains(body, "/login/password") {
			t.Fatal("Expected the password method to be excluded from the MFA page")
		}
		if !strings.Contains(body, "/login/otp") || !strings.Contains(body, user.Email()) {
			t.Fatalf("Expected the OTP method in the MFA page:\n%s", body)
		}

		// repeating the same method doesn't satisfy MFA
		res, _ = b.submit("/oauth2/users/login/password", map[string]string{"password": "1234567890"})
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)
		b.follow(res)

		// OTP (no email input in the MFA step - the identified record is used)
		res, body = b.submit("/oauth2/users/login/otp", nil)
		b.expectStatus(res, body, http.StatusOK)
		oauth2SetOTPPassword(t, app, session.Id, "12345678")

		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		code := b.expectCode(res, oauth2TestIssuer)

		session = b.sessionByCode(code)
		methods := session.DistinctAuthMethods(time.Now().Add(-time.Hour))
		if !slices.Contains(methods, core.AuthSessionMethodPassword) || !slices.Contains(methods, core.AuthSessionMethodOTP) {
			t.Fatalf("Expected password and otp amr, got %v", session.AuthMethods())
		}
	})

	t.Run("otp + password", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA(""))

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res, body := b.submit("/oauth2/users/login/otp", map[string]string{"email": "test2@example.com"})
		b.expectStatus(res, body, http.StatusOK)
		oauth2SetOTPPassword(t, app, b.sessionByHandle(handle).Id, "12345678")

		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)

		res, body = b.follow(res)
		if !strings.Contains(body, "/login/password") || strings.Contains(body, "/login/otp\"") {
			t.Fatalf("Expected only the password (and providers) methods:\n%s", body)
		}

		res, _ = b.submit("/oauth2/users/login/password", map[string]string{"password": "1234567890"})
		b.expectCode(res, oauth2TestIssuer)
	})

	t.Run("wrong second factor", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA(""))

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res, body := b.submit("/oauth2/users/login/otp", map[string]string{"email": "test2@example.com"})
		b.expectStatus(res, body, http.StatusOK)
		oauth2SetOTPPassword(t, app, b.sessionByHandle(handle).Id, "12345678")
		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		b.follow(res)

		res, body = b.submit("/oauth2/users/login/password", map[string]string{"password": "wrong"})
		b.expectStatus(res, body, http.StatusBadRequest)
		if !strings.Contains(body, "Invalid login credentials.") || !strings.Contains(body, "Additional verification") {
			t.Fatalf("Expected MFA page with generic error:\n%s", body)
		}
	})

	t.Run("first factor outside the MFA duration", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA(""))

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)

		// age the first factor
		session := b.sessionByHandle(handle)
		methods := session.AuthMethods()
		methods[0].Time = types.NowDateTime().Add(-time.Hour)
		session.SetAuthMethods(methods)
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}

		res, _ = b.submit("/oauth2/users/login/otp", nil)
		oauth2SetOTPPassword(t, app, session.Id, "12345678")
		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})

		// only 1 method within the MFA duration -> still MFA
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)
	})

	t.Run("MFA rule not matching the record", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA("email = 'test@example.com'"))

		// test2 is not matching the MFA rule -> single factor
		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		b.expectCode(b.loginPassword("users", "test2@example.com", "1234567890"), oauth2TestIssuer)

		// test is matching the MFA rule -> MFA
		b2 := newOAuth2Browser(t, app)
		b2.startLogin("users", "app", nil)
		oauth2ExpectRedirect(t, b2.loginPassword("users", "test@example.com", "1234567890"), oauth2TestPages+"/login/mfa?", nil)
	})

	t.Run("second factor of another record", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA(""))

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		session := b.sessionByHandle(handle)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		b.follow(res)

		// an OTP of another record bound to the same session (e.g. requested before the first factor)
		other := oauth2FindRecord(t, app, "users", "test3@example.com")
		otp := core.NewOTP(app)
		otp.SetCollectionRef(other.Collection().Id)
		otp.SetRecordRef(other.Id)
		otp.SetSessionRef(session.Id)
		otp.SetPassword("87654321")
		if err := app.Save(otp); err != nil {
			t.Fatal(err)
		}

		res, body := b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "87654321"})
		b.expectStatus(res, body, http.StatusBadRequest)

		if s := oauth2ReloadSession(t, app, session.Id); s.RecordRef() == other.Id || len(s.AuthMethods()) != 1 {
			t.Fatalf("Expected the actor to remain unchanged, got %q %v", s.RecordRef(), s.AuthMethods())
		}
	})
}

func TestOAuth2ServerOTP(t *testing.T) {
	t.Parallel()

	t.Run("request and verify (bound to the session)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) { c.OTP.Enabled = true })

		user := oauth2FindRecord(t, app, "users", "test@example.com")

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		session := b.sessionByHandle(handle)

		res, body := b.submit("/oauth2/users/login/otp", map[string]string{"email": "test@example.com"})
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, "If an account with the provided email exists") {
			t.Fatalf("Expected the enumeration safe notice:\n%s", body)
		}

		otp := oauth2SetOTPPassword(t, app, session.Id, "12345678")
		if otp.RecordRef() != user.Id || otp.SentTo() != user.Email() {
			t.Fatalf("Unexpected OTP %v", otp.PublicExport())
		}

		// the session doesn't have an actor until the code is verified
		if s := oauth2ReloadSession(t, app, session.Id); s.RecordRef() != "" {
			t.Fatal("Expected no actor before the OTP verification")
		}

		// another session can't use the OTP
		other := newOAuth2Browser(t, app)
		other.startLogin("users", "app", nil)
		res, body = other.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		other.expectStatus(res, body, http.StatusBadRequest)
		if !strings.Contains(body, "Invalid or expired code.") {
			t.Fatalf("Expected invalid code error:\n%s", body)
		}

		// wrong code
		res, body = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "00000000"})
		b.expectStatus(res, body, http.StatusBadRequest)

		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		b.expectCode(res, oauth2TestIssuer)

		// single use
		if _, err := app.FindOTPById(otp.Id); err == nil {
			t.Fatal("Expected the used OTP to be deleted")
		}

		// the OTP was sent to the record email -> verified upgrade
		if u := oauth2FindRecord(t, app, "users", "test@example.com"); !u.Verified() {
			t.Fatal("Expected the record to be verified")
		}
	})

	t.Run("unknown email (enumeration safe)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) { c.OTP.Enabled = true })

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)

		res, existingBody := b.submit("/oauth2/users/login/otp", map[string]string{"email": "test@example.com"})
		b.expectStatus(res, existingBody, http.StatusOK)

		b2 := newOAuth2Browser(t, app)
		b2.startLogin("users", "app", nil)
		res, missingBody := b2.submit("/oauth2/users/login/otp", map[string]string{"email": "missing@example.com"})
		b2.expectStatus(res, missingBody, http.StatusOK)

		if regexpReplaceVariable(existingBody) != strings.Replace(regexpReplaceVariable(missingBody), hiddenField(missingBody, "auth_state"), hiddenField(existingBody, "auth_state"), -1) {
			t.Fatal("Expected identical responses for existing and missing emails")
		}

		total, _ := app.CountRecords(core.CollectionNameOTPs)
		if total != 1 {
			t.Fatalf("Expected only 1 OTP, got %d", total)
		}
	})

	cliSetup := func(t testing.TB) (*tests.TestApp, *core.Record) {
		app, _ := tests.NewTestApp()

		oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers, func(c *core.Collection) {
			c.OTP.Enabled = true
		})
		oauth2StubClient(t, app, core.CollectionNameSuperusers, "dashboard", oauth2FirstParty, func(c *core.OAuth2Client) {
			c.SetScopes([]string{"openid"})
		})

		return app, oauth2FindRecord(t, app, core.CollectionNameSuperusers, "test@example.com")
	}

	// created outside of a flow (e.g. "superuser otp" command)
	newCLIOTP := func(t testing.TB, app core.App, superuser *core.Record, pass string) *core.OTP {
		otp := core.NewOTP(app)
		otp.SetCollectionRef(superuser.Collection().Id)
		otp.SetRecordRef(superuser.Id)
		otp.SetPassword(pass)
		if err := app.Save(otp); err != nil {
			t.Fatal(err)
		}
		return otp
	}

	expectUnbound := func(t testing.TB, app core.App, otpId string) {
		t.Helper()
		otp, err := app.FindOTPById(otpId)
		if err != nil || otp.SessionRef() != "" {
			t.Fatalf("Expected the CLI OTP to exist and to remain unbound, got %v", err)
		}
	}

	t.Run("CLI-style unbound OTP", func(t *testing.T) {
		app, superuser := cliSetup(t)
		defer app.Cleanup()

		cliOTP := newCLIOTP(t, app, superuser, "11223344")

		// another (attacker) flow can't use the unbound OTP without identifying the record
		attacker := newOAuth2Browser(t, app)
		attacker.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
		res, body := attacker.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "11223344"})
		attacker.expectStatus(res, body, http.StatusBadRequest)

		// identifying the record by an OTP request doesn't claim the unbound OTP
		b := newOAuth2Browser(t, app)
		handle := b.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
		res, body = b.submit("/oauth2/_superusers/login/otp", map[string]string{"email": superuser.Email()})
		b.expectStatus(res, body, http.StatusOK)
		expectUnbound(t, app, cliOTP.Id)
		if s := b.sessionByHandle(handle); s.OTPRecordRef() != superuser.Id || s.RecordRef() != "" {
			t.Fatalf("Expected the OTP request to identify (but not authenticate) the record, got %q %q", s.OTPRecordRef(), s.RecordRef())
		}

		// a second session that has identified the record could also verify it
		c := newOAuth2Browser(t, app)
		c.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
		res, body = c.submit("/oauth2/_superusers/login/otp", map[string]string{"email": superuser.Email()})
		c.expectStatus(res, body, http.StatusOK)
		expectUnbound(t, app, cliOTP.Id)

		// wrong code
		res, body = c.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "00000000"})
		c.expectStatus(res, body, http.StatusBadRequest)
		expectUnbound(t, app, cliOTP.Id)

		// note: the superusers OTP auth is always combined with MFA
		mfaRes, _ := b.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "11223344"})
		oauth2ExpectRedirect(t, mfaRes, "/oauth2/_superusers/login/mfa?", nil)

		// consumed on success
		if _, err := app.FindOTPById(cliOTP.Id); err == nil {
			t.Fatal("Expected the CLI OTP to be consumed")
		}
		res, body = c.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "11223344"})
		c.expectStatus(res, body, http.StatusBadRequest)

		b.follow(mfaRes)
		res, _ = b.submit("/oauth2/_superusers/login/password", map[string]string{"password": "1234567890"})
		b.expectCode(res, "http://localhost:8090/oauth2/_superusers")

		// the record identified by another factor (MFA step) could verify an unbound OTP
		cliOTP2 := newCLIOTP(t, app, superuser, "55667788")

		b2 := newOAuth2Browser(t, app)
		b2.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
		res = b2.loginPassword(core.CollectionNameSuperusers, superuser.Email(), "1234567890")
		oauth2ExpectRedirect(t, res, "/oauth2/_superusers/login/mfa?", nil)
		expectUnbound(t, app, cliOTP2.Id)

		b2.follow(res)
		res, _ = b2.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "55667788"})
		b2.expectCode(res, "http://localhost:8090/oauth2/_superusers")

		if _, err := app.FindOTPById(cliOTP2.Id); err == nil {
			t.Fatal("Expected the second CLI OTP to be consumed")
		}
	})

	t.Run("CLI-style unbound OTP of another record", func(t *testing.T) {
		app, superuser := cliSetup(t)
		defer app.Cleanup()

		other, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, "test2@example.com")
		if err != nil {
			t.Fatal(err)
		}

		cliOTP := newCLIOTP(t, app, other, "11223344")

		// a session that identified another record can't use it
		b := newOAuth2Browser(t, app)
		b.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
		res, body := b.submit("/oauth2/_superusers/login/otp", map[string]string{"email": superuser.Email()})
		b.expectStatus(res, body, http.StatusOK)
		res, body = b.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "11223344"})
		b.expectStatus(res, body, http.StatusBadRequest)
		expectUnbound(t, app, cliOTP.Id)
	})

	t.Run("CLI-style unbound OTP per record attempts limit", func(t *testing.T) {
		app, superuser := cliSetup(t)
		defer app.Cleanup()

		cliOTP := newCLIOTP(t, app, superuser, "11223344")

		// the per record limit is shared by all sessions (5 attempts / 180s)
		for i := 0; i < 6; i++ {
			b := newOAuth2Browser(t, app)
			b.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
			res, body := b.submit("/oauth2/_superusers/login/otp", map[string]string{"email": superuser.Email()})
			b.expectStatus(res, body, http.StatusOK)

			res, body = b.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "00000000"})
			if i < 5 {
				b.expectStatus(res, body, http.StatusBadRequest)
			} else {
				b.expectStatus(res, body, http.StatusTooManyRequests)
			}
		}

		// still limited even with the correct code
		b := newOAuth2Browser(t, app)
		b.startLogin(core.CollectionNameSuperusers, "dashboard", map[string]string{"scope": "openid"})
		b.submit("/oauth2/_superusers/login/otp", map[string]string{"email": superuser.Email()})
		res, body := b.submit("/oauth2/_superusers/login/otp/verify", map[string]string{"code": "11223344"})
		b.expectStatus(res, body, http.StatusTooManyRequests)
		expectUnbound(t, app, cliOTP.Id)
	})
}

func TestOAuth2ServerSignup(t *testing.T) {
	t.Parallel()

	t.Run("allowed (guests createRule)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		var createRequests int
		app.OnRecordCreateRequest("users").BindFunc(func(e *core.RecordRequestEvent) error {
			createRequests++
			if e.Auth != nil {
				return errors.New("expected guest request")
			}
			return e.Next()
		})

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res, body := b.get(hrefLink(b.lastHTML, "/signup?"))
		b.expectStatus(res, body, http.StatusOK)

		// validation errors of the regular create path are shown
		res, body = b.submit("/oauth2/users/signup", map[string]string{
			"email":           "invalid",
			"password":        "1234567890",
			"passwordConfirm": "1234567890",
		})
		b.expectStatus(res, body, http.StatusBadRequest)
		if !strings.Contains(body, "email") {
			t.Fatalf("Expected email validation error:\n%s", body)
		}

		res, body = b.submit("/oauth2/users/signup", map[string]string{
			"email":           "new@example.com",
			"password":        "1234567890",
			"passwordConfirm": "0987654321",
		})
		b.expectStatus(res, body, http.StatusBadRequest)

		res, _ = b.submit("/oauth2/users/signup", map[string]string{
			"email":           "new@example.com",
			"password":        "1234567890",
			"passwordConfirm": "1234567890",
		})
		code := b.expectCode(res, oauth2TestIssuer)

		if createRequests != 2 {
			t.Fatalf("Expected 2 record create requests (through the regular create path), got %d", createRequests)
		}

		created := oauth2FindRecord(t, app, "users", "new@example.com")
		session := b.sessionByCode(code)
		if session.RecordRef() != created.Id || !session.HasAuthMethod(core.AuthSessionMethodPassword) {
			t.Fatalf("Expected the created record password factor, got %q %v", session.RecordRef(), session.AuthMethods())
		}
		if session.Id != b.sessionByCode(code).Id || handle == "" {
			t.Fatal("Unexpected flow session")
		}
	})

	t.Run("denied (nil createRule)", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("clients", "other", nil)

		if strings.Contains(b.lastHTML, "/signup") {
			t.Fatal("Unexpected signup link")
		}

		loginHTML := b.lastHTML

		res, body := b.get("/oauth2/clients/signup?auth_state=" + handle)
		b.expectStatus(res, body, http.StatusNotFound)

		b.lastHTML = loginHTML
		res, body = b.submit("/oauth2/clients/signup", map[string]string{
			"email":           "new@example.com",
			"password":        "1234567890",
			"passwordConfirm": "1234567890",
		})
		b.expectStatus(res, body, http.StatusNotFound)

		if _, err := app.FindAuthRecordByEmail("clients", "new@example.com"); err == nil {
			t.Fatal("Expected no created record")
		}
	})

	t.Run("createRule expression rejecting guests", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
			c.CreateRule = types.Pointer("@request.auth.id != ''")
		})

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		b.get(hrefLink(b.lastHTML, "/signup?"))

		res, body := b.submit("/oauth2/users/signup", map[string]string{
			"email":           "new@example.com",
			"password":        "1234567890",
			"passwordConfirm": "1234567890",
		})
		b.expectStatus(res, body, http.StatusBadRequest)

		if _, err := app.FindAuthRecordByEmail("users", "new@example.com"); err == nil {
			t.Fatal("Expected no created record")
		}
	})
}

func TestOAuth2ServerSessionHooks(t *testing.T) {
	t.Parallel()

	t.Run("OnAuthSessionStepRequest fires and could reject", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		calls := []string{}
		app.OnAuthSessionStepRequest("users").BindFunc(func(e *core.AuthSessionStepRequestEvent) error {
			calls = append(calls, e.Method+":"+e.Record.Email())
			if e.Record.Email() == "test2@example.com" {
				return errors.New("rejected")
			}
			return e.Next()
		})

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		b.expectStatus(res, b.lastHTML, http.StatusBadRequest)
		if s := b.sessionByHandle(handle); s.RecordRef() != "" {
			t.Fatal("Expected the rejected factor to not identify the actor")
		}

		b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

		if !slices.Equal(calls, []string{"password:test2@example.com", "password:test@example.com"}) {
			t.Fatalf("Unexpected step calls %v", calls)
		}
	})

	t.Run("OnAuthSessionCompleteRequest fires, reduces scopes and could reject", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		var completions []bool
		app.OnAuthSessionCompleteRequest().BindFunc(func(e *core.AuthSessionCompleteRequestEvent) error {
			completions = append(completions, e.SSO)
			if e.Record.Email() == "test2@example.com" {
				return errors.New("rejected")
			}
			// drop the email scope
			e.Scopes = slices.DeleteFunc(e.Scopes, func(s string) bool { return s == "email" })
			// adding scopes is ignored
			e.Scopes = append(e.Scopes, "posts:read")
			return e.Next()
		})

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		b.expectError(b.loginPassword("users", "test2@example.com", "1234567890"), "access_denied")
		if s := b.sessionByHandle(handle); s.Status() != core.AuthSessionStatusFailed {
			t.Fatalf("Expected failed session, got %q", s.Status())
		}

		b2 := newOAuth2Browser(t, app)
		b2.startLogin("users", "app", nil)
		code := b2.expectCode(b2.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)
		if s := b2.sessionByCode(code); !slices.Equal(s.Scopes(), []string{"openid"}) {
			t.Fatalf("Expected reduced scopes [openid], got %v", s.Scopes())
		}

		// SSO completion also triggers the hook
		b2.expectCode(b2.authorize("users", "app", nil), oauth2TestIssuer)

		if !slices.Equal(completions, []bool{false, false, true}) {
			t.Fatalf("Unexpected completions %v", completions)
		}
	})

	t.Run("OnOAuth2AuthorizeRequest could reject", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		app.OnOAuth2AuthorizeRequest("users").BindFunc(func(e *core.OAuth2AuthorizeRequestEvent) error {
			if e.Record == nil || e.Client.ClientId() != "app" || e.RedirectURI != oauth2TestRedirectURI || e.State != "test_state" || e.Nonce != "test_nonce" {
				t.Errorf("Unexpected authorize event data")
			}
			return errors.New("rejected")
		})

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		b.expectError(b.loginPassword("users", "test@example.com", "1234567890"), "access_denied")
	})
}

func TestOAuth2ServerCustomFactorRoute(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)

	// register a custom factor route via the programmatic API
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	r.POST("/oauth2/{collection}/login/custom", func(e *core.RequestEvent) error {
		session, err := apis.LoadAuthSession(e)
		if err != nil {
			return e.BadRequestError("Invalid sign-in request.", err)
		}

		record, err := e.App.FindAuthRecordByEmail("users", "test3@example.com")
		if err != nil {
			return err
		}

		if err := apis.AddAuthSessionFactor(e, session, record, "custom", "magic"); err != nil {
			return e.BadRequestError("Failed to authenticate.", err)
		}

		return apis.ContinueAuthSession(e, session)
	})
	mux, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	b.handler = mux

	handle := b.startLogin("users", "app", nil)

	// without binding cookie
	stranger := b.clone(false)
	res, _ := stranger.post("/oauth2/users/login/custom", oauth2URLValues(map[string]string{"auth_state": handle}))
	stranger.expectStatus(res, "", http.StatusBadRequest)

	res, _ = b.post("/oauth2/users/login/custom", oauth2URLValues(map[string]string{"auth_state": handle}))
	code := b.expectCode(res, oauth2TestIssuer)

	session := b.sessionByCode(code)
	if !session.HasAuthMethod("custom") || session.AuthMethods()[0].Provider != "magic" {
		t.Fatalf("Expected custom factor, got %v", session.AuthMethods())
	}
}

func TestOAuth2ServerRateLimitLabels(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		label  string
		action func(b *oauth2Browser) *http.Response
	}{
		{"users:oauth2LoginPassword", func(b *oauth2Browser) *http.Response {
			return b.loginPassword("users", "test@example.com", "wrong")
		}},
		{"*:auth", func(b *oauth2Browser) *http.Response {
			return b.loginPassword("users", "test@example.com", "wrong")
		}},
		{"users:oauth2LoginOTP", func(b *oauth2Browser) *http.Response {
			res, _ := b.submit("/oauth2/users/login/otp", map[string]string{"email": "missing@example.com"})
			return res
		}},
		{"users:oauth2LoginOTPVerify", func(b *oauth2Browser) *http.Response {
			res, _ := b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "123"})
			return res
		}},
		{"users:oauth2Authorize", func(b *oauth2Browser) *http.Response {
			return b.authorize("users", "app", nil)
		}},
		{"users:oauth2Token", func(b *oauth2Browser) *http.Response {
			res, _ := b.tokenRequest("users", map[string]string{"client_id": "app", "grant_type": "authorization_code", "code": "x"})
			return res
		}},
	}

	for _, s := range scenarios {
		t.Run(s.label, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			oauth2AuthorizeSetup(t, app)
			oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) { c.OTP.Enabled = true })

			b := newOAuth2Browser(t, app)
			b.startLogin("users", "app", nil)
			loginHTML := b.lastHTML

			app.Settings().RateLimits.Enabled = true
			app.Settings().RateLimits.Rules = []core.RateLimitRule{{Label: s.label, MaxRequests: 1, Duration: 100}}
			if err := app.Save(app.Settings()); err != nil {
				t.Fatal(err)
			}

			if res := s.action(b); res.StatusCode == http.StatusTooManyRequests {
				t.Fatal("Expected the first request to be allowed")
			}

			b.lastHTML = loginHTML
			if res := s.action(b); res.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("Expected 429, got %d", res.StatusCode)
			}
		})
	}
}

func TestOAuth2ServerAuthAlertOnCompletion(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)
	oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) {
		c.AuthAlert.Enabled = true
	})

	user := oauth2FindRecord(t, app, "users", "test@example.com")

	countOrigins := func() int {
		origins, err := app.FindAllAuthOriginsByRecord(user)
		if err != nil {
			t.Fatal(err)
		}
		return len(origins)
	}

	initial := countOrigins()

	b := newOAuth2Browser(t, app)
	b.startLogin("users", "app", nil)
	b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

	// the auth origin is registered on the interactive session completion
	afterLogin := countOrigins()
	if afterLogin != initial+1 {
		t.Fatalf("Expected a new auth origin, got %d -> %d", initial, afterLogin)
	}

	// the SSO reuse is not an interactive login (no new alerts/origins)
	b.expectCode(b.authorize("users", "app", nil), oauth2TestIssuer)
	if countOrigins() != afterLogin {
		t.Fatal("Expected no new auth origins on SSO reuse")
	}
}

func TestOAuth2ServerVerifiedUpgradeKeepsFlow(t *testing.T) {
	t.Parallel()

	// note: users test@example.com is unverified and has pre-existing external auths
	// (aka. its verified upgrade rotates the tokenKey and ends all of its sessions)
	setup := func(t testing.TB, modifiers ...func(c *core.Collection)) (*tests.TestApp, *core.Record) {
		app, _ := tests.NewTestApp()

		oauth2AuthorizeSetup(t, app)
		oauth2PrepareIssuer(t, app, "users", append([]func(c *core.Collection){oauth2EnableMFA("")}, modifiers...)...)

		user := oauth2FindRecord(t, app, "users", "test@example.com")
		if user.Verified() {
			t.Fatal("Expected unverified user")
		}
		if auths, _ := app.FindAllExternalAuthsByRecord(user); len(auths) == 0 {
			t.Fatal("Expected pre-existing external auths")
		}

		return app, user
	}

	// otherSessions creates unrelated sessions of the user that must be ended by the verified upgrade
	otherSessions := func(t testing.TB, app *tests.TestApp, user *core.Record) (string, *core.AuthSession, *core.AuthSession) {
		access, session := oauth2AccessToken(t, app, oauth2FindClient(t, app, "app"), user, []string{"openid"})
		_, root := oauth2StubSSO(t, app, user, types.NowDateTime())
		return access, session, root
	}

	expectUpgraded := func(t testing.TB, app *tests.TestApp, user *core.Record, otherAccess string, others ...*core.AuthSession) {
		t.Helper()

		fresh := oauth2FindRecord(t, app, "users", user.Email())
		if !fresh.Verified() || fresh.TokenKey() == user.TokenKey() {
			t.Fatalf("Expected verified record with rotated tokenKey, got verified=%v", fresh.Verified())
		}

		for _, s := range others {
			if r := oauth2ReloadSession(t, app, s.Id); r.Status() != core.AuthSessionStatusEnded {
				t.Fatalf("Expected the other session %q to be ended, got %q", s.Id, r.Status())
			}
		}

		if _, err := app.FindAuthRecordByToken(otherAccess, core.TokenTypeAuth); err == nil {
			t.Fatal("Expected the other access token to be rejected")
		}
	}

	expectCompleted := func(t testing.TB, b *oauth2Browser, code string, oldRootId string) {
		t.Helper()

		session := b.sessionByCode(code)

		root := oauth2ReloadSession(t, b.app, session.Parent())
		if !root.IsRoot() || !root.IsActive() || root.Id == oldRootId {
			t.Fatalf("Expected the flow to be re-rooted on a new active root, got %q (old %q)", root.Id, oldRootId)
		}
		if !strings.HasPrefix(b.cookies["pb_session"], root.Id+".") {
			t.Fatal("Expected the new root SSO cookie")
		}

		res, data := b.exchange("users", "app", code, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected successful code exchange, got %d %v", res.StatusCode, data)
		}

		access, _ := data["access_token"].(string)
		if _, err := b.app.FindAuthRecordByToken(access, core.TokenTypeAuth); err != nil {
			t.Fatalf("Expected valid access token, got %v", err)
		}
	}

	t.Run("OTP second factor (MFA)", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		otherAccess, otherSession, otherRoot := otherSessions(t, app, user)

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		res := b.loginPassword("users", user.Email(), "1234567890")
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)
		b.follow(res)

		res, body := b.submit("/oauth2/users/login/otp", nil)
		b.expectStatus(res, body, http.StatusOK)
		oauth2SetOTPPassword(t, app, b.sessionByHandle(handle).Id, "12345678")

		res, body = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		if res.Header.Get("Location") == "" {
			t.Fatalf("Expected code redirect, got %d %s", res.StatusCode, body)
		}
		code := b.expectCode(res, oauth2TestIssuer)

		expectUpgraded(t, app, user, otherAccess, otherSession, otherRoot)
		if auths, _ := app.FindAllExternalAuthsByRecord(user); len(auths) != 0 {
			t.Fatalf("Expected the pre-existing external auths to be deleted, got %d", len(auths))
		}
		expectCompleted(t, b, code, "")
	})

	t.Run("OTP step-up of a reused SSO root", func(t *testing.T) {
		app, user := setup(t)
		defer app.Cleanup()

		otherAccess, otherSession, otherRoot := otherSessions(t, app, user)

		cookie, root := oauth2StubSSO(t, app, user, types.NowDateTime())
		b := newOAuth2Browser(t, app)
		b.cookies["pb_session"] = strings.TrimPrefix(cookie, "pb_session=")

		res := b.authorize("users", "app", nil)
		query := oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", map[string]string{"auth_state": "*"})
		session := b.sessionByHandle(query.Get("auth_state"))
		b.follow(res)

		b.submit("/oauth2/users/login/otp", nil)
		oauth2SetOTPPassword(t, app, session.Id, "12345678")

		res, body := b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "12345678"})
		if res.Header.Get("Location") == "" {
			t.Fatalf("Expected code redirect, got %d %s", res.StatusCode, body)
		}
		code := b.expectCode(res, oauth2TestIssuer)

		// the reused root is ended by the upgrade (as any other session of the record)
		expectUpgraded(t, app, user, otherAccess, otherSession, otherRoot, root)
		expectCompleted(t, b, code, root.Id)
	})

	t.Run("upstream OAuth2 second factor (MFA)", func(t *testing.T) {
		app, user := setup(t, oauth2EnableFakeProvider)
		defer app.Cleanup()

		otherAccess, otherSession, otherRoot := otherSessions(t, app, user)

		upstreamCode := "upgrade_" + security.RandomString(10)
		oauth2FakeUpstreamInstance().stubUser(upstreamCode, &auth.AuthUser{Id: "fake_upgrade_" + security.RandomString(5), Email: user.Email()})

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		res := b.loginPassword("users", user.Email(), "1234567890")
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/mfa?", nil)
		b.follow(res)

		state, _ := oauth2StartUpstream(t, b)
		res, _ = b.get("/api/oauth2-redirect?code=" + upstreamCode + "&state=" + url.QueryEscape(state))
		oauth2ExpectRedirect(t, res, oauth2TestPages+"/login/continue?", nil)

		res, body := b.follow(res)
		if res.Header.Get("Location") == "" {
			t.Fatalf("Expected code redirect, got %d %s", res.StatusCode, body)
		}
		code := b.expectCode(res, oauth2TestIssuer)

		expectUpgraded(t, app, user, otherAccess, otherSession, otherRoot)
		expectCompleted(t, b, code, "")
	})
}

func TestOAuth2AttackLoginCSRF(t *testing.T) {
	t.Parallel()

	scenarios := []struct {
		name    string
		headers map[string]string
		csrf    func(b *oauth2Browser) string
	}{
		{"cross-site Sec-Fetch-Site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": oauth2TestOrigin}, nil},
		{"same-site (sibling subdomain) Sec-Fetch-Site", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": oauth2TestOrigin}, nil},
		{"foreign Origin", map[string]string{"Origin": "https://evil.example.com"}, nil},
		{"foreign Referer without Origin", map[string]string{"Referer": "https://evil.example.com/x"}, nil},
		{"null Origin (sandboxed iframe)", map[string]string{"Origin": "null"}, nil},
		{"missing csrf", map[string]string{"Origin": oauth2TestOrigin}, func(b *oauth2Browser) string { return "" }},
		{"mismatched csrf", map[string]string{"Origin": oauth2TestOrigin}, func(b *oauth2Browser) string { return oauth2TestCSRF }},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			app := oauth2AttackApp(t)

			b := newOAuth2Browser(t, app)
			handle := b.startLogin("users", "app", nil)

			csrf := hiddenField(b.lastHTML, "csrf")
			if s.csrf != nil {
				csrf = s.csrf(b)
			}

			form := url.Values{
				"auth_state": {handle},
				"csrf":       {csrf},
				"identity":   {"test@example.com"},
				"password":   {"1234567890"},
			}

			headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			for k, v := range s.headers {
				headers[k] = v
			}

			res, body := b.do(http.MethodPost, "/oauth2/users/login/password", form.Encode(), headers)
			if res.StatusCode != http.StatusBadRequest || res.Header.Get("Location") != "" || !strings.Contains(body, "Invalid or expired form submission") {
				t.Fatalf("Expected rejected form submission, got %d %q", res.StatusCode, res.Header.Get("Location"))
			}

			if n := oauth2CountFactors(t, app, handle); n != 0 {
				t.Fatalf("Expected no factor, got %d", n)
			}
		})
	}
}

func TestOAuth2AttackMFABypass(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (*tests.TestApp, *oauth2Browser, string) {
		app := oauth2AttackApp(t)
		oauth2PrepareIssuer(t, app, "users", oauth2EnableMFA(""))

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		oauth2ExpectRedirect(t, res, "/oauth2/users/login/mfa?", map[string]string{"auth_state": "*"})
		b.follow(res)

		return app, b, handle
	}

	t.Run("same method twice", func(t *testing.T) {
		_, b, _ := setup(t)

		res := b.loginPassword("users", "test2@example.com", "1234567890")
		oauth2ExpectRedirect(t, res, "/oauth2/users/login/mfa?", map[string]string{"auth_state": "*", "code": ""})
	})

	t.Run("second factor of another record", func(t *testing.T) {
		app, b, handle := setup(t)

		// the password form ignores the identity once the actor is identified
		res := b.loginPassword("users", "test3@example.com", "1234567890")
		if loc := res.Header.Get("Location"); strings.Contains(loc, "code=") {
			t.Fatalf("Unexpected code redirect %q", loc)
		}

		// an OTP of another record (e.g. requested before the first factor) is not accepted
		other := oauth2FindRecord(t, app, "users", "test3@example.com")
		session := b.sessionByHandle(handle)
		otp := core.NewOTP(app)
		otp.SetCollectionRef(other.Collection().Id)
		otp.SetRecordRef(other.Id)
		otp.SetSessionRef(session.Id)
		otp.SetPassword("123456")
		if err := app.Save(otp); err != nil {
			t.Fatal(err)
		}

		b.get("/oauth2/users/login/mfa?auth_state=" + url.QueryEscape(handle))
		res, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "123456"})
		if res.StatusCode != http.StatusBadRequest || strings.Contains(res.Header.Get("Location"), "code=") {
			t.Fatalf("Expected rejected OTP of another record, got %d %q", res.StatusCode, res.Header.Get("Location"))
		}
		if b.sessionByHandle(handle).Status() != core.AuthSessionStatusPending {
			t.Fatal("Expected the flow to stay pending")
		}
	})

	t.Run("first factor outside of the MFA window", func(t *testing.T) {
		app, b, handle := setup(t)

		session := b.sessionByHandle(handle)
		methods := session.AuthMethods()
		methods[0].Time = types.NowDateTime().Add(-time.Hour)
		session.SetAuthMethods(methods)
		if err := app.Save(session); err != nil {
			t.Fatal(err)
		}

		b.get("/oauth2/users/login/mfa?auth_state=" + url.QueryEscape(handle))
		b.submit("/oauth2/users/login/otp", nil)
		oauth2SetOTPPassword(t, app, session.Id, "654321")

		res, _ := b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "654321"})
		oauth2ExpectRedirect(t, res, "/oauth2/users/login/mfa?", map[string]string{"auth_state": "*", "code": ""})
	})

	t.Run("pending flow can't skip to consent", func(t *testing.T) {
		_, b, handle := setup(t)

		res, _ := b.get("/oauth2/users/consent?auth_state=" + url.QueryEscape(handle))
		oauth2ExpectRedirect(t, res, "/oauth2/users/login/mfa?", map[string]string{"auth_state": "*"})

		res, _ = b.submit("/oauth2/users/consent", map[string]string{"decision": "allow"})
		if strings.Contains(res.Header.Get("Location"), "code=") {
			t.Fatalf("Unexpected code redirect %q", res.Header.Get("Location"))
		}
	})
}

func TestOAuth2AttackOTP(t *testing.T) {
	t.Parallel()

	t.Run("brute force is rate limited per record", func(t *testing.T) {
		app := oauth2AttackApp(t)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) { c.OTP.Enabled = true })

		b := newOAuth2Browser(t, app)
		handle := b.startLogin("users", "app", nil)
		b.submit("/oauth2/users/login/otp", map[string]string{"email": "test2@example.com"})
		oauth2SetOTPPassword(t, app, b.sessionByHandle(handle).Id, "111111")

		var last *http.Response
		for i := 0; i < 6; i++ {
			last, _ = b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "000000"})
		}
		if last.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("Expected 429 after too many attempts, got %d", last.StatusCode)
		}

		// even the right code is rejected while limited
		res, _ := b.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "111111"})
		if res.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("Expected 429 for the right code while limited, got %d", res.StatusCode)
		}
	})

	t.Run("OTP of another session and reuse", func(t *testing.T) {
		app := oauth2AttackApp(t)
		oauth2PrepareIssuer(t, app, "users", func(c *core.Collection) { c.OTP.Enabled = true })

		victim := newOAuth2Browser(t, app)
		victimHandle := victim.startLogin("users", "app", nil)
		victim.submit("/oauth2/users/login/otp", map[string]string{"email": "test2@example.com"})
		oauth2SetOTPPassword(t, app, victim.sessionByHandle(victimHandle).Id, "222222")

		// the attacker knows the code but uses it in its own flow
		attacker := newOAuth2Browser(t, app)
		attacker.startLogin("users", "app", nil)
		attacker.submit("/oauth2/users/login/otp", map[string]string{"email": "test3@example.com"})
		res, _ := attacker.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "222222"})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected the OTP of another session to be rejected, got %d %q", res.StatusCode, res.Header.Get("Location"))
		}

		// single use
		res, _ = victim.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "222222"})
		victim.expectCode(res, oauth2TestIssuer)

		replay := newOAuth2Browser(t, app)
		replayHandle := replay.startLogin("users", "app", nil)
		_ = replayHandle
		res, _ = replay.submit("/oauth2/users/login/otp/verify", map[string]string{"code": "222222"})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected the used OTP to be rejected, got %d", res.StatusCode)
		}
	})
}

func TestOAuth2ServerPromptCreate(t *testing.T) {
	t.Parallel()

	t.Run("opens the hosted signup page of the flow and continues like a login", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)

		res := b.authorize("users", "app", map[string]string{"prompt": "create"})
		b.expectStatus(res, "", http.StatusFound)
		query := oauth2ExpectRedirect(t, res, "/oauth2/users/signup?", map[string]string{"auth_state": "*"})

		res, body := b.follow(res)
		b.expectStatus(res, body, http.StatusOK)
		if !strings.Contains(body, `name="passwordConfirm"`) || hiddenField(body, "auth_state") != query.Get("auth_state") {
			t.Fatalf("Expected the signup form of the same flow:\n%s", body)
		}
		// the same flow could still switch to the login page
		if hrefLink(body, "/login?") == "" {
			t.Fatalf("Expected a login link:\n%s", body)
		}

		res, _ = b.submit("/oauth2/users/signup", map[string]string{
			"email":           "created@example.com",
			"password":        "1234567890",
			"passwordConfirm": "1234567890",
		})
		code := b.expectCode(res, oauth2TestIssuer)

		created := oauth2FindRecord(t, app, "users", "created@example.com")
		session := b.sessionByCode(code)
		if session.RecordRef() != created.Id || !session.HasAuthMethod(core.AuthSessionMethodPassword) {
			t.Fatalf("Expected the created record password factor, got %q %v", session.RecordRef(), session.AuthMethods())
		}

		tokenRes, tokens := b.exchange("users", "app", code, nil)
		b.expectStatus(tokenRes, "", http.StatusOK)
		if tokens["access_token"] == nil || tokens["id_token"] == nil {
			t.Fatalf("Expected tokens, got %v", tokens)
		}
	})

	t.Run("doesn't reuse an existing SSO session", func(t *testing.T) {
		app, _ := tests.NewTestApp()
		defer app.Cleanup()

		oauth2AuthorizeSetup(t, app)

		b := newOAuth2Browser(t, app)
		b.startLogin("users", "app", nil)
		b.expectCode(b.loginPassword("users", "test@example.com", "1234567890"), oauth2TestIssuer)

		// sanity: a regular authorize reuses the SSO session
		res := b.authorize("users", "app", nil)
		b.expectCode(res, oauth2TestIssuer)

		res = b.authorize("users", "app", map[string]string{"prompt": "create"})
		oauth2ExpectRedirect(t, res, "/oauth2/users/signup?", map[string]string{"auth_state": "*"})
	})

	scenarios := []struct {
		name        string
		collection  string
		clientId    string
		prompt      string
		redirectURI string
	}{
		{"nil createRule", "clients", "other", "create", oauth2TestRedirectURI},
		// the built-in dashboard client redirect URI is the same origin dashboard
		{"superusers", core.CollectionNameSuperusers, "pb_dashboard", "create", oauth2TestOrigin + "/_/"},
		{"combined with none", "users", "app", "none create", oauth2TestRedirectURI},
	}

	for _, s := range scenarios {
		t.Run("unsupported: "+s.name, func(t *testing.T) {
			app, _ := tests.NewTestApp()
			defer app.Cleanup()

			oauth2AuthorizeSetup(t, app)
			oauth2PrepareIssuer(t, app, core.CollectionNameSuperusers)

			b := newOAuth2Browser(t, app)
			res := b.authorize(s.collection, s.clientId, map[string]string{
				"prompt":       s.prompt,
				"redirect_uri": s.redirectURI,
			})

			oauth2ExpectRedirect(t, res, s.redirectURI+"?", map[string]string{
				"error":             "invalid_request",
				"error_description": "*",
				"state":             "test_state",
				"code":              "",
			})

			total, _ := app.CountRecords(core.CollectionNameAuthSessions)
			if total != 0 {
				t.Fatalf("Expected no flow session, got %d", total)
			}
		})
	}
}

func TestOAuth2ServerDiscoveryPromptCreate(t *testing.T) {
	t.Parallel()

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	oauth2AuthorizeSetup(t, app)

	b := newOAuth2Browser(t, app)

	res, body := b.get("/oauth2/users/.well-known/openid-configuration")
	b.expectStatus(res, body, http.StatusOK)
	if !strings.Contains(body, `"prompt_values_supported":["none","login","consent","create"]`) {
		t.Fatalf("Expected prompt create for the users issuer:\n%s", body)
	}

	res, body = b.get("/oauth2/clients/.well-known/openid-configuration")
	b.expectStatus(res, body, http.StatusOK)
	if !strings.Contains(body, `"prompt_values_supported":["none","login","consent"]`) {
		t.Fatalf("Expected no prompt create for the clients issuer (no signup):\n%s", body)
	}
}
