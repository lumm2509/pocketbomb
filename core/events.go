package core

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/lumm2509/pocketbomb/tools/filesystem"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/llm"
	"github.com/lumm2509/pocketbomb/tools/mailer"
	"github.com/lumm2509/pocketbomb/tools/router"
	"github.com/lumm2509/pocketbomb/tools/search"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"
	"github.com/lumm2509/pocketbomb/tools/webhooks"
	"golang.org/x/crypto/acme/autocert"
)

type HookTagger interface {
	HookTags() []string
}

// -------------------------------------------------------------------

type baseModelEventData struct {
	Model Model
}

func (e *baseModelEventData) Tags() []string {
	if e.Model == nil {
		return nil
	}

	if ht, ok := e.Model.(HookTagger); ok {
		return ht.HookTags()
	}

	return []string{e.Model.TableName()}
}

// -------------------------------------------------------------------

type baseRecordEventData struct {
	Record *Record
}

func (e *baseRecordEventData) Tags() []string {
	if e.Record == nil {
		return nil
	}

	return e.Record.HookTags()
}

// -------------------------------------------------------------------

type baseCollectionEventData struct {
	Collection *Collection
}

// @todo consider storing the original collection name and use that as a tag
// to avoid the  ambiguity when the collection is being modified (#7613);
// for new collection also maybe return empty tags?
func (e *baseCollectionEventData) Tags() []string {
	if e.Collection == nil {
		return nil
	}

	tags := make([]string, 0, 2)

	if e.Collection.Id != "" {
		tags = append(tags, e.Collection.Id)
	}

	if e.Collection.Name != "" {
		tags = append(tags, e.Collection.Name)
	}

	return tags
}

// -------------------------------------------------------------------
// App events data
// -------------------------------------------------------------------

type BootstrapEvent struct {
	hook.Event
	App App
}

type TerminateEvent struct {
	hook.Event
	App       App
	IsRestart bool
}

type BackupEvent struct {
	hook.Event
	App     App
	Context context.Context
	Name    string   // the name of the backup to create/restore.
	Exclude []string // list of dir entries to exclude from the backup create/restore.
}

type ServeEvent struct {
	hook.Event
	App         App
	Router      *router.Router[*RequestEvent]
	Server      *http.Server
	CertManager *autocert.Manager

	// Listener allow specifying a custom network listener.
	//
	// Leave it nil to use the default net.Listen("tcp", e.Server.Addr).
	Listener net.Listener

	// InstallerFunc is the "installer" function that is called after
	// successful server tcp bind but only if there is no explicit
	// superuser record created yet.
	//
	// It runs in a separate goroutine and its default value is [apis.DefaultInstallerFunc].
	//
	// It receives a system superuser record as argument that you can use to generate
	// a short-lived installer token (e.g. systemSuperuser.NewInstallerToken(30 * time.Minute))
	// and pass it to your installer page (the token could be used only
	// with the /api/installer endpoints, e.g. to create the first superuser,
	// and it is never accepted as auth token).
	//
	// Set it to nil if you want to skip the installer.
	InstallerFunc func(app App, systemSuperuser *Record, baseURL string) error

	// @todo experimental
	//
	// UIExtensions is a list with the superuser UI extensions.
	UIExtensions []UIExtension
}

type UIExtension struct {
	// Name is the name of the extension.
	// It is also used as path segment for the registered public extension endpoint
	// (e.g. /_/extensions/{name}/*)
	Name string

	// FS is the extension file system.
	FS fs.FS
}

// -------------------------------------------------------------------
// Settings events data
// -------------------------------------------------------------------

type SettingsListRequestEvent struct {
	hook.Event
	*RequestEvent

	Settings *Settings
}

type SettingsUpdateRequestEvent struct {
	hook.Event
	*RequestEvent

	OldSettings *Settings
	NewSettings *Settings
}

type SettingsReloadEvent struct {
	hook.Event
	App App
}

// -------------------------------------------------------------------
// Mailer events data
// -------------------------------------------------------------------

type MailerEvent struct {
	hook.Event
	App App

	Mailer  mailer.Mailer
	Message *mailer.Message
}

type MailerRecordEvent struct {
	MailerEvent
	baseRecordEventData
	Meta map[string]any
}

// -------------------------------------------------------------------
// Filesystem events data
// -------------------------------------------------------------------

type FilesystemNewWriterEvent struct {
	hook.Event
	*filesystem.NewWriterEvent

	App App
}

type FilesystemDeleteEvent struct {
	hook.Event
	*filesystem.DeleteEvent

	App App
}

// -------------------------------------------------------------------
// LLM events data
// -------------------------------------------------------------------

type baseLLMEventData struct {
	// Profile is the name of the LLM profile used to create the client (if any).
	Profile string

	// ProviderName is the name of the resolved LLM provider config.
	ProviderName string

	// CallInfo is the optional caller information attached to the request context
	// (see [WithLLMCallInfo]). It is never nil.
	CallInfo *LLMCallInfo
}

// Tags returns the LLM event tags (aka. the profile and the provider names).
func (e *baseLLMEventData) Tags() []string {
	tags := make([]string, 0, 2)

	if e.Profile != "" {
		tags = append(tags, e.Profile)
	}

	if e.ProviderName != "" {
		tags = append(tags, e.ProviderName)
	}

	return tags
}

// LLMRequestEvent is triggered before every [App.NewLLMClient] Generate and Stream call.
//
// Handlers could modify the e.Request or return an error to abort it.
type LLMRequestEvent struct {
	hook.Event
	*llm.BeforeRequestEvent
	baseLLMEventData

	App App
}

// LLMResponseEvent is triggered after every [App.NewLLMClient] Generate and Stream call
// (including the failed ones).
//
// Handlers could modify the e.Response or replace/clear the e.Error
// (e.Next() returns e.Error).
type LLMResponseEvent struct {
	hook.Event
	*llm.AfterResponseEvent
	baseLLMEventData

	App App
}

// -------------------------------------------------------------------
// Model events data
// -------------------------------------------------------------------

const (
	ModelEventTypeCreate   = "create"
	ModelEventTypeUpdate   = "update"
	ModelEventTypeDelete   = "delete"
	ModelEventTypeValidate = "validate"
)

type ModelEvent struct {
	hook.Event
	App App
	baseModelEventData
	Context context.Context

	// Could be any of the ModelEventType* constants, like:
	// - create
	// - update
	// - delete
	// - validate
	Type string
}

type ModelErrorEvent struct {
	Error error
	ModelEvent
}

// -------------------------------------------------------------------
// Record events data
// -------------------------------------------------------------------

type RecordEvent struct {
	hook.Event
	App App
	baseRecordEventData
	Context context.Context

	// Could be any of the ModelEventType* constants, like:
	// - create
	// - update
	// - delete
	// - validate
	Type string
}

type RecordErrorEvent struct {
	Error error
	RecordEvent
}

func syncModelEventWithRecordEvent(me *ModelEvent, re *RecordEvent) {
	me.App = re.App
	me.Context = re.Context
	me.Type = re.Type

	// @todo enable if after profiling doesn't have significant impact
	// 		 skip for now to avoid excessive checks and assume that the
	// 		 Model and the Record fields still points to the same instance
	//
	// if _, ok := me.Model.(*Record); ok {
	// 	me.Model = re.Record
	// } else if proxy, ok := me.Model.(RecordProxy); ok {
	// 	proxy.SetProxyRecord(re.Record)
	// }
}

func syncRecordEventWithModelEvent(re *RecordEvent, me *ModelEvent) {
	re.App = me.App
	re.Context = me.Context
	re.Type = me.Type
}

func newRecordEventFromModelEvent(me *ModelEvent) (*RecordEvent, bool) {
	record, ok := me.Model.(*Record)
	if !ok {
		proxy, ok := me.Model.(RecordProxy)
		if !ok {
			return nil, false
		}
		record = proxy.ProxyRecord()
	}

	re := new(RecordEvent)
	re.App = me.App
	re.Context = me.Context
	re.Type = me.Type
	re.Record = record

	return re, true
}

func newRecordErrorEventFromModelErrorEvent(me *ModelErrorEvent) (*RecordErrorEvent, bool) {
	recordEvent, ok := newRecordEventFromModelEvent(&me.ModelEvent)
	if !ok {
		return nil, false
	}

	re := new(RecordErrorEvent)
	re.RecordEvent = *recordEvent
	re.Error = me.Error

	return re, true
}

func syncModelErrorEventWithRecordErrorEvent(me *ModelErrorEvent, re *RecordErrorEvent) {
	syncModelEventWithRecordEvent(&me.ModelEvent, &re.RecordEvent)
	me.Error = re.Error
}

func syncRecordErrorEventWithModelErrorEvent(re *RecordErrorEvent, me *ModelErrorEvent) {
	syncRecordEventWithModelEvent(&re.RecordEvent, &me.ModelEvent)
	re.Error = me.Error
}

// -------------------------------------------------------------------
// Collection events data
// -------------------------------------------------------------------

type CollectionEvent struct {
	hook.Event
	App App
	baseCollectionEventData
	Context context.Context

	// Could be any of the ModelEventType* constants, like:
	// - create
	// - update
	// - delete
	// - validate
	Type string
}

type CollectionErrorEvent struct {
	Error error
	CollectionEvent
}

func syncModelEventWithCollectionEvent(me *ModelEvent, ce *CollectionEvent) {
	me.App = ce.App
	me.Context = ce.Context
	me.Type = ce.Type
	me.Model = ce.Collection
}

func syncCollectionEventWithModelEvent(ce *CollectionEvent, me *ModelEvent) {
	ce.App = me.App
	ce.Context = me.Context
	ce.Type = me.Type
	if c, ok := me.Model.(*Collection); ok {
		ce.Collection = c
	}
}

func newCollectionEventFromModelEvent(me *ModelEvent) (*CollectionEvent, bool) {
	record, ok := me.Model.(*Collection)
	if !ok {
		return nil, false
	}

	ce := new(CollectionEvent)
	ce.App = me.App
	ce.Context = me.Context
	ce.Type = me.Type
	ce.Collection = record

	return ce, true
}

func newCollectionErrorEventFromModelErrorEvent(me *ModelErrorEvent) (*CollectionErrorEvent, bool) {
	collectionevent, ok := newCollectionEventFromModelEvent(&me.ModelEvent)
	if !ok {
		return nil, false
	}

	ce := new(CollectionErrorEvent)
	ce.CollectionEvent = *collectionevent
	ce.Error = me.Error

	return ce, true
}

func syncModelErrorEventWithCollectionErrorEvent(me *ModelErrorEvent, ce *CollectionErrorEvent) {
	syncModelEventWithCollectionEvent(&me.ModelEvent, &ce.CollectionEvent)
	me.Error = ce.Error
}

func syncCollectionErrorEventWithModelErrorEvent(ce *CollectionErrorEvent, me *ModelErrorEvent) {
	syncCollectionEventWithModelEvent(&ce.CollectionEvent, &me.ModelEvent)
	ce.Error = me.Error
}

// -------------------------------------------------------------------
// File API events data
// -------------------------------------------------------------------

type FileTokenRequestEvent struct {
	hook.Event
	*RequestEvent
	baseRecordEventData

	Token string
}

type FileDownloadRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record     *Record
	FileField  *FileField
	ServedPath string
	ServedName string

	// ThumbError indicates the a thumb wasn't able to be generated
	// (e.g. because it didn't satisfy the support image formats or it timed out).
	//
	// Note that PocketBase fallbacks to the original file in case of a thumb error,
	// but developers can check the field and provide their own custom thumb generation if necessary.
	ThumbError error
}

// -------------------------------------------------------------------
// Collection API events data
// -------------------------------------------------------------------

type CollectionsListRequestEvent struct {
	hook.Event
	*RequestEvent

	Collections []*Collection
	Result      *search.Result
}

type CollectionsImportRequestEvent struct {
	hook.Event
	*RequestEvent

	CollectionsData []map[string]any
	DeleteMissing   bool
}

type CollectionRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData
}

// -------------------------------------------------------------------
// Realtime API events data
// -------------------------------------------------------------------

type RealtimeConnectRequestEvent struct {
	hook.Event
	*RequestEvent

	Client subscriptions.Client

	// IdleTimeout specifies the max duration to wait for a new message
	// before closing the connection.
	//
	// Modifying the value after the connection has been established has no effect.
	//
	// Defaults to 5 minutes.
	IdleTimeout time.Duration

	// MaxTimeout specifies the maximum duration a realtime connection
	// can remain open (including even if there are ongoing messages).
	//
	// Once the specified duration expires, the current connection will
	// be terminated, until a client reconnect is issued (if the client is still active).
	//
	// Modifying the value after the connection has been established has no effect.
	//
	// Defaults to 30 minutes.
	MaxTimeout time.Duration
}

type RealtimeMessageEvent struct {
	hook.Event
	*RequestEvent

	Client  subscriptions.Client
	Message *subscriptions.Message
}

type RealtimeSubscribeRequestEvent struct {
	hook.Event
	*RequestEvent

	Client        subscriptions.Client
	Subscriptions []string
}

// -------------------------------------------------------------------
// Record CRUD API events data
// -------------------------------------------------------------------

type RecordsListRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	// @todo consider removing and maybe add as generic to the search.Result?
	Records []*Record
	Result  *search.Result
}

type RecordRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record *Record
}

type RecordEnrichEvent struct {
	hook.Event
	App App
	baseRecordEventData

	RequestInfo *RequestInfo
}

// -------------------------------------------------------------------
// GraphQL API events data
// -------------------------------------------------------------------

type GraphQLRequestEvent struct {
	hook.Event
	*RequestEvent

	Query         string
	Variables     map[string]any
	OperationName string
}

// -------------------------------------------------------------------
// Auth Record API events data
// -------------------------------------------------------------------

type RecordRequestPasswordResetRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record *Record
}

type RecordConfirmPasswordResetRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record *Record
}

type RecordRequestVerificationRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record *Record
}

type RecordConfirmVerificationRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record *Record
}

type RecordRequestEmailChangeRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record   *Record
	NewEmail string
}

type RecordConfirmEmailChangeRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Record   *Record
	NewEmail string
}

// -------------------------------------------------------------------
// OAuth2 server API events data
// -------------------------------------------------------------------

type AuthSessionStepRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	// Session is the auth session of the hosted login flow.
	Session *AuthSession

	// Record is the auth record identified by the factor.
	Record *Record

	// Method is the factor method (e.g. "password", "otp", "oauth2").
	Method string

	// Provider is the upstream OAuth2 provider name (oauth2 factors only).
	Provider string
}

// AuthSessionCompleteRequestEvent is the [App.OnAuthSessionCompleteRequest] hook event.
//
// Note that the extra token claims are not part of this event
// (use [OAuth2TokenRequestEvent.IdTokenClaims] instead).
type AuthSessionCompleteRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	// Session is the completed auth session.
	Session *AuthSession

	// Client is the OAuth2 client of the auth session.
	Client *OAuth2Client

	// Record is the authenticated auth record (aka. the actor).
	Record *Record

	// Scopes is the list of the requested (and allowed) scopes that will be granted.
	//
	// It could be reduced by the hook handlers.
	Scopes []string

	// SSO indicates that the authentication was completed by reusing
	// an existing root SSO session (aka. without interactive login).
	SSO bool
}

type OAuth2AuthorizeRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	// Client is the OAuth2 client requesting the authorization.
	Client *OAuth2Client

	// Record is the authenticated auth record (aka. the end-user).
	Record *Record

	// Scopes is the list of the requested (and allowed) scopes.
	Scopes []string

	RedirectURI string
	State       string
	Nonce       string
}

type OAuth2TokenRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	// GrantType is the token request grant type
	// (e.g. "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange").
	GrantType string

	Client  *OAuth2Client
	Record  *Record
	Session *AuthSession
	Scopes  []string

	// IdTokenClaims is an optional map with custom claims that will be
	// added to the generated id_token (see [OIDCIdTokenOptions.ExtraClaims]).
	IdTokenClaims map[string]any
}

type OAuth2RevokeRequestEvent struct {
	hook.Event
	*RequestEvent
	baseCollectionEventData

	Client  *OAuth2Client
	Session *AuthSession

	// TokenTypeHint is the optional RFC 7009 token type hint
	// ("access_token" or "refresh_token").
	TokenTypeHint string
}

// -------------------------------------------------------------------
// Applications events data
// -------------------------------------------------------------------

type ApplicationManifestImportEvent struct {
	hook.Event
	App App

	// Manifest is the parsed, validated and normalized manifest to import.
	Manifest *ApplicationManifest

	// SourceFormat is the manifest source format ("toml" or "json").
	SourceFormat string

	// CreatedBy is the optional id of the staff record that imports the manifest.
	CreatedBy string

	// Result is the import result (available after e.Next()).
	Result *ApplicationManifestImportResult
}

type ApplicationInstallEvent struct {
	hook.Event
	App App

	Application *Application

	// Permissions is the installation grant.
	Permissions Permissions

	// InstalledBy is the optional id of the staff record that installs the application.
	InstalledBy string

	// Result is the install result with the plain client secret (available after e.Next()).
	Result *ApplicationInstallResult
}

type ApplicationInstallationUpdateEvent struct {
	hook.Event
	App App

	Installation *ApplicationInstallation

	// VersionRef is the new installation version (empty = keep the current one).
	VersionRef string

	// Permissions is the new installation grant (nil = keep the current one).
	Permissions *Permissions
}

type ApplicationSecretRotateEvent struct {
	hook.Event
	App App

	Installation *ApplicationInstallation

	// Client and ClientSecret are the managed OAuth2 client and its new
	// plain secret (available after e.Next()).
	Client       *OAuth2Client
	ClientSecret string
}

type ApplicationUninstallEvent struct {
	hook.Event
	App App

	Installation *ApplicationInstallation
}

type ApplicationManifestImportRequestEvent struct {
	hook.Event
	*RequestEvent

	// Manifest is the parsed, validated and normalized manifest to import
	// (it is also the manifest built from the "create custom application" form).
	Manifest *ApplicationManifest

	// SourceFormat is the manifest source format ("toml" or "json").
	SourceFormat string

	// Result is the import result (available after e.Next()).
	Result *ApplicationManifestImportResult
}

type ApplicationInstallRequestEvent struct {
	hook.Event
	*RequestEvent

	Application *Application

	// Permissions is the installation grant.
	Permissions Permissions

	// Result is the install result with the plain client secret (available after e.Next()).
	Result *ApplicationInstallResult
}

// GraphQLSchemaCollectionChange defines a single collection change of an applied schema
// (Old is nil for the created collections and New for the deleted ones).
type GraphQLSchemaCollectionChange struct {
	Old *Collection
	New *Collection
}

// GraphQLSchemaApplyRequestEvent is the event of the dashboard GraphQL schema editor apply request.
//
// It is triggered inside the apply transaction (e.App is the transactional app)
// and the changes are available after calling e.Next().
type GraphQLSchemaApplyRequestEvent struct {
	hook.Event
	*RequestEvent

	Schema           string
	PlanHash         string
	AllowDestructive bool

	// Changes are the applied collection changes.
	Changes []GraphQLSchemaCollectionChange

	// MigrationFile is the name of the migration generated by the
	// migrations writer (the apply fails with changes and without it).
	MigrationFile string
}

type ApplicationProxyRequestEvent struct {
	hook.Event
	*RequestEvent

	Application  *Application
	Installation *ApplicationInstallation
}

type ApplicationUninstallRequestEvent struct {
	hook.Event
	*RequestEvent

	Application  *Application
	Installation *ApplicationInstallation
}

// -------------------------------------------------------------------
// Webhooks events data
// -------------------------------------------------------------------

type baseWebhookEventData struct {
	// Webhook is the related webhook subscription
	// (could be nil in [WebhookDeliveryEvent] if the subscription was deleted).
	Webhook *Webhook

	// Delivery is the processed delivery.
	Delivery *webhooks.Delivery

	// Topic is the human friendly event topic (e.g. "posts.create").
	Topic string

	// Test indicates a manually triggered test delivery.
	Test bool
}

// Tags returns the webhook event tags (aka. the subscription id and the topic in its human friendly and storage formats).
func (e *baseWebhookEventData) Tags() []string {
	tags := make([]string, 0, 3)

	if e.Webhook != nil {
		tags = append(tags, e.Webhook.Id)
	} else if e.Delivery != nil {
		tags = append(tags, e.Delivery.SubscriptionId)
	}

	if e.Topic != "" {
		tags = append(tags, e.Topic)
	}

	if e.Delivery != nil && e.Delivery.Event.Topic != e.Topic {
		tags = append(tags, e.Delivery.Event.Topic)
	}

	return tags
}

// WebhookSendEvent is triggered before each webhook delivery attempt.
//
// Handlers could modify e.Request (headers and body; the signature is calculated from the final body),
// skip the attempt by not calling e.Next() (the delivery is marked as "disabled")
// or return an error (the attempt is marked as failed and retried).
type WebhookSendEvent struct {
	hook.Event
	baseWebhookEventData

	App App

	Request *webhooks.Request
}

// WebhookDeliveryEvent is triggered after each processed webhook delivery attempt.
//
// Attempt is nil for the disabled (aka. not sent) deliveries.
type WebhookDeliveryEvent struct {
	hook.Event
	baseWebhookEventData

	App App

	Attempt *webhooks.Attempt
}
