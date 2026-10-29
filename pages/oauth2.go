package pages

// OAuth2 server hosted pages view data.
//
// Every flow form submits the opaque AuthState handle and the CSRF token
// as hidden fields (see [Form]).

// Form defines the common hidden fields of the hosted pages forms.
type Form struct {
	AuthState string
	CSRF      string
}

// Client defines the OAuth2 client info shown on the hosted pages.
type Client struct {
	Name string
	Logo string
}

// Provider defines a single upstream OAuth2 provider sign-in link.
type Provider struct {
	Name        string
	DisplayName string
	URL         string
}

// LoginPage defines the "oauth2/login" page data.
type LoginPage struct {
	Form
	Client

	Error  string
	Notice string

	// password
	PasswordAction string
	IdentityLabel  string
	LoginHint      string

	// otp
	OTPAction string

	// oauth2
	Providers []Provider

	// links
	SignupURL              string
	PasswordResetURL       string
	VerificationRequestURL string
}

// HasMethods reports whether at least one sign-in method is available.
func (p LoginPage) HasMethods() bool {
	return p.PasswordAction != "" || p.OTPAction != "" || len(p.Providers) > 0
}

// OTPPage defines the "oauth2/otp" (one-time code entry) page data.
type OTPPage struct {
	Form
	Client

	Error    string
	Action   string
	BackURL  string
	SentInfo string
}

// MFAPage defines the "oauth2/mfa" (additional factor) page data.
type MFAPage struct {
	Form
	Client

	Error     string
	UserLabel string

	PasswordAction string
	OTPAction      string
	Providers      []Provider
}

// HasMethods reports whether at least one additional factor method is available.
func (p MFAPage) HasMethods() bool {
	return p.PasswordAction != "" || p.OTPAction != "" || len(p.Providers) > 0
}

// ConsentPage defines the "oauth2/consent" page data.
type ConsentPage struct {
	Form
	Client

	Action    string
	UserLabel string
	Scopes    []string
}

// SignupPage defines the "oauth2/signup" page data.
type SignupPage struct {
	Form
	Client

	Error    string
	Action   string
	Email    string
	LoginURL string
}

// PasswordResetPage defines the "oauth2/password_reset" (request) page data.
type PasswordResetPage struct {
	Form

	Error    string
	Notice   string
	Action   string
	Email    string
	LoginURL string
}

// TokenFormPage defines the data of the account confirmation pages
// that submit a mail token ("oauth2/password_reset_confirm",
// "oauth2/verify_email" and "oauth2/email_change_confirm").
type TokenFormPage struct {
	CSRF string

	Error  string
	Action string
	Token  string
	Email  string
}

// MessagePage defines the "oauth2/message" page data.
type MessagePage struct {
	Heading   string
	Message   string
	ErrorCode string

	// optional link
	LinkURL   string
	LinkLabel string

	// optional confirmation form
	Action      string
	ActionLabel string
	CSRF        string
	Params      map[string]string
}
