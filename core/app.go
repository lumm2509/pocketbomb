// Package core is the backbone of PocketBase.
//
// It defines the main PocketBase App interface and its base implementation.
package core

import (
	"context"
	"log/slog"
	"time"

	"github.com/lumm2509/pocketbomb/tools/cron"
	"github.com/lumm2509/pocketbomb/tools/filesystem"
	"github.com/lumm2509/pocketbomb/tools/hook"
	"github.com/lumm2509/pocketbomb/tools/llm"
	"github.com/lumm2509/pocketbomb/tools/mailer"
	"github.com/lumm2509/pocketbomb/tools/store"
	"github.com/lumm2509/pocketbomb/tools/subscriptions"
	"github.com/pocketbase/dbx"
)

// App defines the main PocketBase app interface.
//
// Note that the interface is not intended to be implemented manually by users
// and instead they should use core.BaseApp (either directly or as embedded field in a custom struct).
//
// This interface exists to make testing easier and to allow users to
// create common and pluggable helpers and methods that doesn't rely
// on a specific wrapped app struct (hence the large interface size).
type App interface {
	// UnsafeWithoutHooks returns a shallow copy of the current app WITHOUT any registered hooks.
	//
	// NB! Note that using the returned app instance may cause data integrity errors
	// since the Record validations and data normalizations (including files uploads)
	// rely on the app hooks to work.
	UnsafeWithoutHooks() App

	// Logger returns the default app logger.
	//
	// If the application is not bootstrapped yet, fallbacks to slog.Default().
	Logger() *slog.Logger

	// IsBootstrapped checks if the application was initialized
	// (aka. whether Bootstrap() was called).
	IsBootstrapped() bool

	// IsTransactional checks if the current app instance is part of a transaction.
	IsTransactional() bool

	// TxInfo returns the transaction associated with the current app instance (if any).
	//
	// Could be used if you want to execute indirectly a function after
	// the related app transaction completes using `app.TxInfo().OnAfterFunc(callback)`.
	TxInfo() *TxAppInfo

	// Bootstrap initializes the application
	// (aka. create data dir, open db connections, load settings, etc.).
	//
	// It calls ClearBootstrap() if the application was already bootstrapped.
	Bootstrap() error

	// ClearBootstrap releases the initialized core app resources
	// (closing db connections, stopping cron ticker, etc.).
	//
	// This method is no-op if the application is not bootstrapped yet.
	ClearBootstrap() error

	// Deprecated: use ClearBootstrap().
	ResetBootstrapState() error

	// DataDir returns the app data directory path.
	DataDir() string

	// EncryptionEnv returns the name of the app secret env key
	// (currently used primarily for optional settings encryption but this may change in the future).
	EncryptionEnv() string

	// IsDev returns whether the app is in dev mode.
	//
	// When enabled logs, executed sql statements, etc. are printed to the stderr.
	IsDev() bool

	// Settings returns the loaded app settings.
	Settings() *Settings

	// Store returns the app runtime store.
	Store() *store.Store[string, any]

	// Cron returns the app cron instance.
	Cron() *cron.Cron

	// SubscriptionsBroker returns the app realtime subscriptions broker instance.
	SubscriptionsBroker() *subscriptions.Broker

	// NewMailClient creates and returns a new SMTP or Sendmail client
	// based on the current app settings.
	NewMailClient() mailer.Mailer

	// NewFilesystem creates a new local or S3 filesystem instance
	// for managing regular app files (ex. record uploads)
	// based on the current app settings.
	//
	// NB! Make sure to call Close() on the returned result
	// after you are done working with it.
	NewFilesystem() (*filesystem.System, error)

	// NewBackupsFilesystem creates a new local or S3 filesystem instance
	// for managing app backups based on the current app settings.
	//
	// NB! Make sure to call Close() on the returned result
	// after you are done working with it.
	NewBackupsFilesystem() (*filesystem.System, error)

	// NewLLMClient creates a new LLM client for the specified profile or
	// provider name (or the default provider if not specified)
	// based on the current app settings and env variables.
	//
	// Returns [ErrLLMNotConfigured] if there are no enabled LLM providers.
	//
	// NB! Make sure to call Close() on the returned result
	// after you are done working with it.
	NewLLMClient(profileOrProvider ...string) (*llm.Client, error)

	// LLMProviders returns the list with the enabled LLM providers
	// (from the app settings and the env variables) without their secrets.
	//
	// The default provider (if any) is always the first list element.
	LLMProviders() []*LLMProviderInfo

	// ReloadSettings reinitializes and reloads the stored application settings.
	ReloadSettings() error

	// CreateBackup creates a new backup of the current app pb_data directory.
	//
	// Backups can be stored on S3 if it is configured in app.Settings().Backups.
	//
	// Please refer to the godoc of the specific core.App implementation
	// for details on the backup procedures.
	CreateBackup(ctx context.Context, name string) error

	// RestoreBackup restores the backup with the specified name and restarts
	// the current running application process.
	//
	// The safely perform the restore it is recommended to have free disk space
	// for at least 2x the size of the restored pb_data backup.
	//
	// Please refer to the godoc of the specific core.App implementation
	// for details on the restore procedures.
	//
	// NB! This feature is experimental and currently is expected to work only on UNIX based systems.
	RestoreBackup(ctx context.Context, name string) error

	// Restart restarts (aka. replaces) the current running application process.
	//
	// NB! It relies on execve which is supported only on UNIX based systems.
	Restart() error

	// RunSystemMigrations applies all new migrations registered in the [core.SystemMigrations] list.
	RunSystemMigrations() error

	// RunAppMigrations applies all new migrations registered in the [core.AppMigrations] list.
	RunAppMigrations() error

	// RunAllMigrations applies all system and app migrations
	// (aka. from both [core.SystemMigrations] and [core.AppMigrations]).
	RunAllMigrations() error

	// ---------------------------------------------------------------
	// DB methods
	// ---------------------------------------------------------------

	// DB returns the default app data.db builder instance.
	//
	// To minimize SQLITE_BUSY errors, it automatically routes the
	// SELECT queries to the underlying concurrent db pool and everything else
	// to the nonconcurrent one.
	//
	// For more finer control over the used connections pools you can
	// call directly ConcurrentDB() or NonconcurrentDB().
	DB() dbx.Builder

	// ConcurrentDB returns the concurrent app data.db builder instance.
	//
	// This method is used mainly internally for executing db read
	// operations in a concurrent/non-blocking manner.
	//
	// Most users should use simply DB() as it will automatically
	// route the query execution to ConcurrentDB() or NonconcurrentDB().
	//
	// In a transaction the ConcurrentDB() and NonconcurrentDB() refer to the same *dbx.TX instance.
	ConcurrentDB() dbx.Builder

	// NonconcurrentDB returns the nonconcurrent app data.db builder instance.
	//
	// The returned db instance is limited only to a single open connection,
	// meaning that it can process only 1 db operation at a time (other queries queue up).
	//
	// This method is used mainly internally and in the tests to execute write
	// (save/delete) db operations as it helps with minimizing the SQLITE_BUSY errors.
	//
	// Most users should use simply DB() as it will automatically
	// route the query execution to ConcurrentDB() or NonconcurrentDB().
	//
	// In a transaction the ConcurrentDB() and NonconcurrentDB() refer to the same *dbx.TX instance.
	NonconcurrentDB() dbx.Builder

	// AuxDB returns the app auxiliary.db builder instance.
	//
	// To minimize SQLITE_BUSY errors, it automatically routes the
	// SELECT queries to the underlying concurrent db pool and everything else
	// to the nonconcurrent one.
	//
	// For more finer control over the used connections pools you can
	// call directly AuxConcurrentDB() or AuxNonconcurrentDB().
	AuxDB() dbx.Builder

	// AuxConcurrentDB returns the concurrent app auxiliary.db builder instance.
	//
	// This method is used mainly internally for executing db read
	// operations in a concurrent/non-blocking manner.
	//
	// Most users should use simply AuxDB() as it will automatically
	// route the query execution to AuxConcurrentDB() or AuxNonconcurrentDB().
	//
	// In a transaction the AuxConcurrentDB() and AuxNonconcurrentDB() refer to the same *dbx.TX instance.
	AuxConcurrentDB() dbx.Builder

	// AuxNonconcurrentDB returns the nonconcurrent app auxiliary.db builder instance.
	//
	// The returned db instance is limited only to a single open connection,
	// meaning that it can process only 1 db operation at a time (other queries queue up).
	//
	// This method is used mainly internally and in the tests to execute write
	// (save/delete) db operations as it helps with minimizing the SQLITE_BUSY errors.
	//
	// Most users should use simply AuxDB() as it will automatically
	// route the query execution to AuxConcurrentDB() or AuxNonconcurrentDB().
	//
	// In a transaction the AuxConcurrentDB() and AuxNonconcurrentDB() refer to the same *dbx.TX instance.
	AuxNonconcurrentDB() dbx.Builder

	// HasTable checks if a table (or view) with the provided name exists (case insensitive).
	// in the data.db.
	HasTable(tableName string) bool

	// AuxHasTable checks if a table (or view) with the provided name exists (case insensitive)
	// in the auxiliary.db.
	AuxHasTable(tableName string) bool

	// TableColumns returns all column names of a single table by its name.
	TableColumns(tableName string) ([]string, error)

	// TableInfo returns the "table_info" pragma result for the specified table.
	TableInfo(tableName string) ([]*TableInfoRow, error)

	// TableIndexes returns a name grouped map with all non empty index of the specified table.
	//
	// Note: This method doesn't return an error on nonexisting table.
	TableIndexes(tableName string) (map[string]string, error)

	// DeleteTable drops the specified table.
	//
	// This method is a no-op if a table with the provided name doesn't exist.
	//
	// NB! Be aware that this method is vulnerable to SQL injection and the
	// "dangerousTableName" argument must come only from trusted input!
	DeleteTable(dangerousTableName string) error

	// DeleteView drops the specified view name.
	//
	// This method is a no-op if a view with the provided name doesn't exist.
	//
	// NB! Be aware that this method is vulnerable to SQL injection and the
	// "dangerousViewName" argument must come only from trusted input!
	DeleteView(dangerousViewName string) error

	// SaveView creates (or updates already existing) persistent SQL view.
	//
	// NB! Be aware that this method is vulnerable to SQL injection and
	// its arguments must come only from trusted input!
	SaveView(dangerousViewName string, dangerousSelectQuery string) error

	// CreateViewFields creates a new FieldsList from the provided select query.
	//
	// There are some caveats:
	// - The select query must have an "id" column.
	// - Wildcard ("*") columns are not supported to avoid accidentally leaking sensitive data.
	//
	// NB! Be aware that this method is vulnerable to SQL injection and the
	// "dangerousSelectQuery" argument must come only from trusted input!
	CreateViewFields(dangerousSelectQuery string) (FieldsList, error)

	// DryRunView executes the provided query by creating a temporary view
	// collection and returning a sample of the resulting query records (if valid).
	//
	// The same caveats from CreateViewFields apply here too.
	//
	// NB! Be aware that this method is vulnerable to SQL injection and the
	// "dangerousSelectQuery" argument must come only from trusted input!
	DryRunView(dangerousSelectQuery string, sampleSize int) (*DryRunViewResult, error)

	// FindRecordByViewFile returns the original Record of the provided view collection file.
	FindRecordByViewFile(viewCollectionModelOrIdentifier any, fileFieldName string, filename string) (*Record, error)

	// Vacuum executes VACUUM on the data.db in order to reclaim unused data db disk space.
	Vacuum() error

	// AuxVacuum executes VACUUM on the auxiliary.db in order to reclaim unused auxiliary db disk space.
	AuxVacuum() error

	// ---------------------------------------------------------------

	// ModelQuery creates a new preconfigured select data.db query with preset
	// SELECT, FROM and other common fields based on the provided model.
	ModelQuery(model Model) *dbx.SelectQuery

	// AuxModelQuery creates a new preconfigured select auxiliary.db query with preset
	// SELECT, FROM and other common fields based on the provided model.
	AuxModelQuery(model Model) *dbx.SelectQuery

	// Delete deletes the specified model from the regular app database.
	Delete(model Model) error

	// Delete deletes the specified model from the regular app database
	// (the context could be used to limit the query execution).
	DeleteWithContext(ctx context.Context, model Model) error

	// AuxDelete deletes the specified model from the auxiliary database.
	AuxDelete(model Model) error

	// AuxDeleteWithContext deletes the specified model from the auxiliary database
	// (the context could be used to limit the query execution).
	AuxDeleteWithContext(ctx context.Context, model Model) error

	// Save validates and saves the specified model into the regular app database.
	//
	// If you don't want to run validations, use [App.SaveNoValidate()].
	Save(model Model) error

	// SaveWithContext is the same as [App.Save()] but allows specifying a context to limit the db execution.
	//
	// If you don't want to run validations, use [App.SaveNoValidateWithContext()].
	SaveWithContext(ctx context.Context, model Model) error

	// SaveNoValidate saves the specified model into the regular app database without performing validations.
	//
	// If you want to also run validations before persisting, use [App.Save()].
	SaveNoValidate(model Model) error

	// SaveNoValidateWithContext is the same as [App.SaveNoValidate()]
	// but allows specifying a context to limit the db execution.
	//
	// If you want to also run validations before persisting, use [App.SaveWithContext()].
	SaveNoValidateWithContext(ctx context.Context, model Model) error

	// AuxSave validates and saves the specified model into the auxiliary app database.
	//
	// If you don't want to run validations, use [App.AuxSaveNoValidate()].
	AuxSave(model Model) error

	// AuxSaveWithContext is the same as [App.AuxSave()] but allows specifying a context to limit the db execution.
	//
	// If you don't want to run validations, use [App.AuxSaveNoValidateWithContext()].
	AuxSaveWithContext(ctx context.Context, model Model) error

	// AuxSaveNoValidate saves the specified model into the auxiliary app database without performing validations.
	//
	// If you want to also run validations before persisting, use [App.AuxSave()].
	AuxSaveNoValidate(model Model) error

	// AuxSaveNoValidateWithContext is the same as [App.AuxSaveNoValidate()]
	// but allows specifying a context to limit the db execution.
	//
	// If you want to also run validations before persisting, use [App.AuxSaveWithContext()].
	AuxSaveNoValidateWithContext(ctx context.Context, model Model) error

	// Validate triggers the OnModelValidate hook for the specified model.
	Validate(model Model) error

	// ValidateWithContext is the same as Validate but allows specifying the ModelEvent context.
	ValidateWithContext(ctx context.Context, model Model) error

	// RunInTransaction wraps fn into a transaction for the regular app database.
	//
	// It is safe to nest RunInTransaction calls as long as you use the callback's txApp.
	RunInTransaction(fn func(txApp App) error) error

	// AuxRunInTransaction wraps fn into a transaction for the auxiliary app database.
	//
	// It is safe to nest RunInTransaction calls as long as you use the callback's txApp.
	AuxRunInTransaction(fn func(txApp App) error) error

	// ---------------------------------------------------------------

	// LogQuery returns a new Log select query.
	LogQuery() *dbx.SelectQuery

	// FindLogById finds a single Log entry by its id.
	FindLogById(id string) (*Log, error)

	// LogsStatsItem returns hourly grouped logs statistics.
	LogsStats(expr dbx.Expression) ([]*LogsStatsItem, error)

	// DeleteOldLogs delete all logs that are created before createdBefore.
	DeleteOldLogs(createdBefore time.Time) error

	// LLMLogQuery returns a new LLMLog select query.
	LLMLogQuery() *dbx.SelectQuery

	// FindLLMLogById finds a single LLMLog entry by its id.
	FindLLMLogById(id string) (*LLMLog, error)

	// LLMLogsStats returns time bucketed (and optionally grouped) LLM logs statistics.
	LLMLogsStats(params LLMLogsStatsParams) ([]*LLMLogsStatsItem, error)

	// LLMLogsTopUsers returns the LLM logs usage aggregated by user (or guest IP)
	// and sorted by the total tokens (or requests) in DESC order.
	LLMLogsTopUsers(params LLMLogsTopUsersParams) ([]*LLMLogsTopUsersItem, error)

	// LLMUsage returns the LLM usage (requests and tokens) matching the specified filter.
	//
	// The result includes also the queued but not yet persisted logs.
	LLMUsage(filter LLMUsageFilter) (*LLMUsage, error)

	// ReserveLLMQuota checks the profile quotas of the provided actor
	// (authRecord or, if nil, the guest ip) and on success registers an in-flight
	// reservation that must be released once the request completes.
	//
	// Returns [*LLMQuotaExceededError] if the quota is exceeded.
	ReserveLLMQuota(profile *LLMProfile, authRecord *Record, ip string) (release func(), err error)

	// WriteLLMLog queues the provided LLM log for async batched write
	// in the auxiliary db (it is no-op if the LLM logs are disabled).
	WriteLLMLog(log *LLMLog)

	// DeleteOldLLMLogs deletes all LLM logs created before the specified date.
	DeleteOldLLMLogs(createdBefore time.Time) error

	// WebhookDeliveryQuery returns a new WebhookDelivery select query.
	WebhookDeliveryQuery() *dbx.SelectQuery

	// FindWebhookDeliveryById finds a single WebhookDelivery entry by its id.
	FindWebhookDeliveryById(id string) (*WebhookDelivery, error)

	// WebhookDeliveriesStats returns time bucketed (and optionally grouped) webhook deliveries statistics.
	WebhookDeliveriesStats(params WebhookDeliveriesStatsParams) ([]*WebhookDeliveriesStatsItem, error)

	// DeleteOldWebhookDeliveries deletes all completed webhook deliveries created before the specified date.
	DeleteOldWebhookDeliveries(createdBefore time.Time) error

	// ---------------------------------------------------------------

	// CollectionQuery returns a new Collection select query.
	CollectionQuery() *dbx.SelectQuery

	// FindCollections finds all collections by the given type(s).
	//
	// If collectionTypes is not set, it returns all collections.
	//
	// Example:
	//
	//	app.FindAllCollections() // all collections
	//	app.FindAllCollections("auth", "view") // only auth and view collections
	FindAllCollections(collectionTypes ...string) ([]*Collection, error)

	// ReloadCachedCollections fetches all collections and caches them into the app store.
	ReloadCachedCollections() error

	// FindCollectionByNameOrId finds a single collection by its name (case insensitive) or id.s
	FindCollectionByNameOrId(nameOrId string) (*Collection, error)

	// FindCachedCollectionByNameOrId is similar to [App.FindCollectionByNameOrId]
	// but retrieves the Collection from the app cache instead of making a db call.
	//
	// NB! This method is suitable for read-only Collection operations.
	//
	// Returns [sql.ErrNoRows] if no Collection is found for consistency
	// with the [App.FindCollectionByNameOrId] method.
	//
	// If you plan making changes to the returned Collection model,
	// use [App.FindCollectionByNameOrId] instead.
	//
	// Caveats:
	//
	//   - The returned Collection should be used only for read-only operations.
	//     Avoid directly modifying the returned cached Collection as it will affect
	//     the global cached value even if you don't persist the changes in the database!
	//   - If you are updating a Collection in a transaction and then call this method before commit,
	//     it'll return the cached Collection state and not the one from the uncommitted transaction.
	//   - The cache is automatically updated on collections db change (create/update/delete).
	//     To manually reload the cache you can call [App.ReloadCachedCollections]
	FindCachedCollectionByNameOrId(nameOrId string) (*Collection, error)

	// FindCollectionReferences returns information for all relation
	// fields referencing the provided collection.
	//
	// If the provided collection has reference to itself then it will be
	// also included in the result. To exclude it, pass the collection id
	// as the excludeIds argument.
	FindCollectionReferences(collection *Collection, excludeIds ...string) (map[*Collection][]Field, error)

	// FindCachedCollectionReferences is similar to [App.FindCollectionReferences]
	// but retrieves the Collection from the app cache instead of making a db call.
	//
	// NB! This method is suitable for read-only Collection operations.
	//
	// If you plan making changes to the returned Collection model,
	// use [App.FindCollectionReferences] instead.
	//
	// Caveats:
	//
	//   - The returned Collection should be used only for read-only operations.
	//     Avoid directly modifying the returned cached Collection as it will affect
	//     the global cached value even if you don't persist the changes in the database!
	//   - If you are updating a Collection in a transaction and then call this method before commit,
	//     it'll return the cached Collection state and not the one from the uncommitted transaction.
	//   - The cache is automatically updated on collections db change (create/update/delete).
	//     To manually reload the cache you can call [App.ReloadCachedCollections].
	FindCachedCollectionReferences(collection *Collection, excludeIds ...string) (map[*Collection][]Field, error)

	// IsCollectionNameUnique checks that there is no existing collection
	// with the provided name (case insensitive!).
	//
	// Note: case insensitive check because the name is used also as
	// table name for the records.
	IsCollectionNameUnique(name string, excludeIds ...string) bool

	// TruncateCollection deletes all records associated with the provided collection.
	//
	// The truncate operation is executed in a single transaction,
	// aka. either everything is deleted or none.
	//
	// Note that this method will also trigger the records related
	// cascade and file delete actions.
	TruncateCollection(collection *Collection) error

	// ImportCollections imports the provided collections data in a single transaction.
	//
	// For existing matching collections, the imported data is unmarshaled on top of the existing model.
	//
	// NB! If deleteMissing is true, ALL NON-SYSTEM COLLECTIONS AND SCHEMA FIELDS,
	// that are not present in the imported configuration, WILL BE DELETED
	// (this includes their related records data).
	ImportCollections(toImport []map[string]any, deleteMissing bool) error

	// ImportCollectionsByMarshaledJSON is the same as [ImportCollections]
	// but accept marshaled json array as import data (usually used for the autogenerated snapshots).
	ImportCollectionsByMarshaledJSON(rawSliceOfMaps []byte, deleteMissing bool) error

	// SyncRecordTableSchema compares the two provided collections
	// and applies the necessary related record table changes.
	//
	// If oldCollection is null, then only newCollection is used to create the record table.
	//
	// This method is automatically invoked as part of a collection create/update/delete operation.
	SyncRecordTableSchema(newCollection *Collection, oldCollection *Collection) error

	// ---------------------------------------------------------------

	// FindAllExternalAuthsByRecord returns all ExternalAuth models
	// linked to the provided auth record.
	FindAllExternalAuthsByRecord(authRecord *Record) ([]*ExternalAuth, error)

	// FindAllExternalAuthsByCollection returns all ExternalAuth models
	// linked to the provided auth collection.
	FindAllExternalAuthsByCollection(collection *Collection) ([]*ExternalAuth, error)

	// FindFirstExternalAuthByExpr returns the first available (the most recent created)
	// ExternalAuth model that satisfies the non-nil expression.
	FindFirstExternalAuthByExpr(expr dbx.Expression) (*ExternalAuth, error)

	// DeleteAllExternalAuthsByRecord deletes all ExternalAuth models associated with the provided record.
	//
	// Returns a combined error with the failed deletes.
	DeleteAllExternalAuthsByRecord(authRecord *Record) error

	// ---------------------------------------------------------------

	// FindAllOTPsByRecord returns all OTP models linked to the provided auth record.
	FindAllOTPsByRecord(authRecord *Record) ([]*OTP, error)

	// FindAllOTPsByCollection returns all OTP models linked to the provided collection.
	FindAllOTPsByCollection(collection *Collection) ([]*OTP, error)

	// FindOTPById returns a single OTP model by its id.
	FindOTPById(id string) (*OTP, error)

	// DeleteAllOTPsByRecord deletes all OTP models associated with the provided record.
	//
	// Returns a combined error with the failed deletes.
	DeleteAllOTPsByRecord(authRecord *Record) error

	// DeleteExpiredOTPs deletes the expired OTPs for all auth collections.
	DeleteExpiredOTPs() error

	// ---------------------------------------------------------------

	// FindWebhookById returns a single Webhook subscription model by its id.
	FindWebhookById(id string) (*Webhook, error)

	// Webhooks returns the app outgoing webhooks service
	// (topics registry, dispatcher, test sends and redeliveries).
	Webhooks() *Webhooks

	// ---------------------------------------------------------------

	// FindAllOAuth2ClientsByCollection returns all OAuth2Client models
	// registered for the provided auth collection.
	FindAllOAuth2ClientsByCollection(collection *Collection) ([]*OAuth2Client, error)

	// FindOAuth2ClientById returns a single OAuth2Client model by its record id.
	FindOAuth2ClientById(id string) (*OAuth2Client, error)

	// FindOAuth2ClientByClientId returns a single OAuth2Client model by its public client_id.
	FindOAuth2ClientByClientId(clientId string) (*OAuth2Client, error)

	// FindAPIKeyById returns a single APIKey model by its record id.
	FindAPIKeyById(id string) (*APIKey, error)

	// FindAPIKeyByToken returns the APIKey model of the provided plain token
	// (looked up by its sha256 hash; the key and client state are not checked).
	FindAPIKeyByToken(plainToken string) (*APIKey, error)

	// HasPublicAPIKeyForOrigin reports whether at least one enabled and not expired
	// public API key has the provided origin in its allowed origins.
	HasPublicAPIKeyForOrigin(origin string) bool

	// FindAllAPIKeysByClient returns all APIKey models of the specified OAuth2 client record id (newest first).
	FindAllAPIKeysByClient(clientId string) ([]*APIKey, error)

	// FindOAuth2ConsentByRecordAndClient returns the remembered consent of the provided auth record for the specified client.
	FindOAuth2ConsentByRecordAndClient(authRecord *Record, client *OAuth2Client) (*OAuth2Consent, error)

	// FindAllOAuth2ConsentsByRecord returns all OAuth2Consent models of the provided auth record.
	FindAllOAuth2ConsentsByRecord(authRecord *Record) ([]*OAuth2Consent, error)

	// ---------------------------------------------------------------
	// RBAC roles
	// ---------------------------------------------------------------

	// FindRoleById returns the role with the specified id.
	FindRoleById(id string) (*Role, error)

	// FindRoleByName returns the role with the specified name.
	FindRoleByName(name string) (*Role, error)

	// FindOwnerRole returns the built-in system Owner role.
	FindOwnerRole() (*Role, error)

	// FindAllRoles returns all roles ordered by name (the system roles first).
	FindAllRoles() ([]*Role, error)

	// FindRolesByIds returns the roles with the specified ids (the missing ones are ignored).
	FindRolesByIds(ids []string) ([]*Role, error)

	// FindAllRoleAssignmentsByRecord returns the explicit role assignments of the provided auth record.
	FindAllRoleAssignmentsByRecord(authRecord *Record) ([]*RoleAssignment, error)

	// FindRecordRoles returns the effective roles of the provided auth record:
	// its explicit role assignments or, if there are none, the collection DefaultRoles.
	FindRecordRoles(authRecord *Record) ([]*Role, error)

	// CountOwners returns the total number of Owner role assignments.
	CountOwners() (int, error)

	// IsOwnerRecord reports whether the provided auth record has an explicit Owner role assignment.
	IsOwnerRecord(authRecord *Record) bool

	// AssignOwnerRole assigns the built-in Owner role to the provided superuser (if not already).
	AssignOwnerRole(superuser *Record) error

	// ---------------------------------------------------------------
	// Applications
	// ---------------------------------------------------------------

	// FindApplicationById returns the application with the specified id.
	FindApplicationById(id string) (*Application, error)

	// FindApplicationByHandle returns the application with the specified handle.
	FindApplicationByHandle(handle string) (*Application, error)

	// FindAllApplications returns all applications ordered by name.
	FindAllApplications() ([]*Application, error)

	// FindApplicationVersionById returns the application version with the specified id.
	FindApplicationVersionById(id string) (*ApplicationVersion, error)

	// FindAllApplicationVersionsByApplication returns all versions of the provided application (newest first).
	FindAllApplicationVersionsByApplication(applicationId string) ([]*ApplicationVersion, error)

	// FindApplicationInstallationById returns the application installation with the specified id.
	FindApplicationInstallationById(id string) (*ApplicationInstallation, error)

	// FindApplicationInstallationByApplication returns the installation of the specified application.
	FindApplicationInstallationByApplication(applicationId string) (*ApplicationInstallation, error)

	// FindApplicationInstallationClient returns the managed OAuth2 client of the provided installation.
	FindApplicationInstallationClient(installationId string) (*OAuth2Client, error)

	// ImportApplicationManifest creates a custom application (or a new immutable version of
	// an existing custom application with the same handle) from the provided manifest.
	ImportApplicationManifest(manifest *ApplicationManifest, sourceFormat string, createdBy string) (*ApplicationManifestImportResult, error)

	// InstallApplication installs the provided application (latest version) with the provided
	// grant and creates its confidential managed OAuth2 client (client_credentials and token_exchange grants)
	// and its managed webhooks.
	//
	// If the manifest has an install_url, the credentials are delivered with a signed install
	// notification and the installation is activated only if it is acknowledged (otherwise it is deleted).
	//
	// The plain client secret is returned only once.
	InstallApplication(application *Application, grant Permissions, installedBy string) (*ApplicationInstallResult, error)

	// RotateApplicationInstallationSecret generates a new client secret for the managed OAuth2 client
	// and a new managed webhooks secret of the provided installation and ends every session of the installation.
	RotateApplicationInstallationSecret(installation *ApplicationInstallation) (*OAuth2Client, string, error)

	// UpdateApplicationInstallation changes the installation version and/or grant and re-syncs its managed webhooks
	// (a version requesting more scopes requires an explicitly submitted grant).
	UpdateApplicationInstallation(installation *ApplicationInstallation, versionRef string, grant *Permissions) error

	// UninstallApplication deletes the provided installation together with its
	// managed OAuth2 client, webhooks and sessions.
	UninstallApplication(installation *ApplicationInstallation) error

	// FindAllWebhooksByApplicationInstallation returns the managed webhooks of the provided installation.
	FindAllWebhooksByApplicationInstallation(installationId string) ([]*Webhook, error)

	// ApplicationCatalogs returns the app applications catalogs service.
	ApplicationCatalogs() *ApplicationCatalogs

	// ImportApplicationCatalogEntry fetches, verifies and imports the current manifest of the
	// specified catalog entry as a catalog application (or as its new version).
	ImportApplicationCatalogEntry(ctx context.Context, sourceName string, handle string, createdBy string) (*ApplicationManifestImportResult, error)

	// ---------------------------------------------------------------

	// SaveOAuth2Consent creates or updates the remembered consent of the provided
	// auth record for the specified client by merging the provided scopes.
	SaveOAuth2Consent(authRecord *Record, client *OAuth2Client, scopes []string) (*OAuth2Consent, error)

	// ---------------------------------------------------------------

	// CreateAuthSession creates and persists a new active auth session for the
	// provided auth record and OAuth2 client (e.g. for custom auth methods,
	// token exchange or tests).
	//
	// The returned session has already attached actor and client
	// so that [AuthSession.NewAccessToken] could be called directly.
	CreateAuthSession(authRecord *Record, client *OAuth2Client, opts AuthSessionOptions) (*AuthSession, error)

	// FindAuthSessionById returns a single AuthSession model by its id.
	FindAuthSessionById(id string) (*AuthSession, error)

	// FindAuthSessionByHandle returns a single AuthSession model whose
	// opaque "auth_state" handle hash matches with the provided plain handle.
	//
	// Note that the returned session could be expired or in a terminal status.
	FindAuthSessionByHandle(plainHandle string) (*AuthSession, error)

	// FindAuthSessionByCode returns a single AuthSession model whose
	// authorization code hash matches with the provided plain code.
	//
	// Note that the returned session could be expired, with already consumed code or in a terminal status.
	FindAuthSessionByCode(plainCode string) (*AuthSession, error)

	// FindAuthSessionByRefreshToken returns a single AuthSession model
	// whose current refresh token hash matches with the provided plain refresh token.
	//
	// Note that the returned session could be expired or in a terminal status.
	FindAuthSessionByRefreshToken(plainToken string) (*AuthSession, error)

	// FindAuthSessionByPrevRefreshToken returns a single AuthSession model
	// whose previous (aka. already rotated) refresh token hash matches with
	// the provided plain refresh token.
	//
	// It could be used for refresh token reuse detection.
	FindAuthSessionByPrevRefreshToken(plainToken string) (*AuthSession, error)

	// FindAllAuthSessionsByRecord returns all AuthSession models of the provided auth record
	// (in any status, ordered by their creation date DESC).
	FindAllAuthSessionsByRecord(authRecord *Record) ([]*AuthSession, error)

	// EndAllAuthSessionsByRecord ends all non-terminal auth sessions of the provided auth record.
	//
	// Returns a combined error with the failed updates.
	EndAllAuthSessionsByRecord(authRecord *Record) error

	// EndAllAuthSessionsByClient ends all non-terminal auth sessions of the provided OAuth2 client.
	//
	// Returns a combined error with the failed updates.
	EndAllAuthSessionsByClient(client *OAuth2Client) error

	// IsAuthSessionRootAlive reports whether the root SSO session of the provided
	// session is still active (always true for the root-less and offline_access sessions).
	IsAuthSessionRootAlive(session *AuthSession) bool

	// EndAuthSession ends the provided auth session (and its children)
	// because of the provided reason (e.g. a detected security issue).
	EndAuthSession(session *AuthSession, reason string) error

	// DeleteExpiredAuthSessions deletes all ended, failed and expired auth sessions.
	DeleteExpiredAuthSessions() error

	// ---------------------------------------------------------------

	// FindAllAuthOriginsByRecord returns all AuthOrigin models linked to the provided auth record (in DESC order).
	FindAllAuthOriginsByRecord(authRecord *Record) ([]*AuthOrigin, error)

	// FindAllAuthOriginsByCollection returns all AuthOrigin models linked to the provided collection (in DESC order).
	FindAllAuthOriginsByCollection(collection *Collection) ([]*AuthOrigin, error)

	// FindAuthOriginById returns a single AuthOrigin model by its id.
	FindAuthOriginById(id string) (*AuthOrigin, error)

	// FindAuthOriginByRecordAndFingerprint returns a single AuthOrigin model
	// by its authRecord relation and fingerprint.
	FindAuthOriginByRecordAndFingerprint(authRecord *Record, fingerprint string) (*AuthOrigin, error)

	// DeleteAllAuthOriginsByRecord deletes all AuthOrigin models associated with the provided record.
	//
	// Returns a combined error with the failed deletes.
	DeleteAllAuthOriginsByRecord(authRecord *Record) error

	// ---------------------------------------------------------------

	// RecordQuery returns a new Record select query from a collection model, id or name.
	//
	// In case a collection id or name is provided and that collection doesn't
	// actually exists, the generated query will be created with a cancelled context
	// and will fail once an executor (Row(), One(), All(), etc.) is called.
	RecordQuery(collectionModelOrIdentifier any) *dbx.SelectQuery

	// FindRecordById finds the Record model by its id.
	FindRecordById(collectionModelOrIdentifier any, recordId string, optFilters ...func(q *dbx.SelectQuery) error) (*Record, error)

	// FindRecordsByIds finds all records by the specified ids.
	// If no records are found, returns an empty slice.
	FindRecordsByIds(collectionModelOrIdentifier any, recordIds []string, optFilters ...func(q *dbx.SelectQuery) error) ([]*Record, error)

	// FindAllRecords finds all records matching specified db expressions.
	//
	// Returns all collection records if no expression is provided.
	//
	// Returns an empty slice if no records are found.
	//
	// Example:
	//
	//	// no extra expressions
	//	app.FindAllRecords("example")
	//
	//	// with extra expressions
	//	expr1 := dbx.HashExp{"email": "test@example.com"}
	//	expr2 := dbx.NewExp("LOWER(username) = {:username}", dbx.Params{"username": "test"})
	//	app.FindAllRecords("example", expr1, expr2)
	FindAllRecords(collectionModelOrIdentifier any, exprs ...dbx.Expression) ([]*Record, error)

	// FindFirstRecordByData returns the first found record matching
	// the provided key-value pair.
	FindFirstRecordByData(collectionModelOrIdentifier any, key string, value any) (*Record, error)

	// FindRecordsByFilter returns limit number of records matching the
	// provided string filter.
	//
	// NB! Use the last "params" argument to bind untrusted user variables!
	//
	// The filter argument is optional and can be empty string to target
	// all available records.
	//
	// The sort argument is optional and can be empty string OR the same format
	// used in the web APIs, ex. "-created,title".
	//
	// If the limit argument is <= 0, no limit is applied to the query and
	// all matching records are returned.
	//
	// Returns an empty slice if no records are found.
	//
	// Example:
	//
	//	app.FindRecordsByFilter(
	//		"posts",
	//		"title ~ {:title} && visible = {:visible}",
	//		"-created",
	//		10,
	//		0,
	//		dbx.Params{"title": "lorem ipsum", "visible": true}
	//	)
	FindRecordsByFilter(
		collectionModelOrIdentifier any,
		filter string,
		sort string,
		limit int,
		offset int,
		params ...dbx.Params,
	) ([]*Record, error)

	// FindFirstRecordByFilter returns the first available record matching the provided filter (if any).
	//
	// NB! Use the last params argument to bind untrusted user variables!
	//
	// Returns sql.ErrNoRows if no record is found.
	//
	// Example:
	//
	//	app.FindFirstRecordByFilter("posts", "")
	//	app.FindFirstRecordByFilter("posts", "slug={:slug} && status='public'", dbx.Params{"slug": "test"})
	FindFirstRecordByFilter(
		collectionModelOrIdentifier any,
		filter string,
		params ...dbx.Params,
	) (*Record, error)

	// CountRecords returns the total number of records in a collection.
	CountRecords(collectionModelOrIdentifier any, exprs ...dbx.Expression) (int64, error)

	// FindAuthRecordByToken finds the auth record associated with the provided JWT
	// (auth, file, verifyEmail, changeEmail, passwordReset types).
	//
	// Optionally specify a list of validTypes to check tokens only from those types.
	//
	// Returns an error if the JWT is invalid, expired or not associated to an auth collection record.
	FindAuthRecordByToken(token string, validTypes ...string) (*Record, error)

	// FindAuthRecordByEmail finds the auth record associated with the provided email.
	//
	// Returns an error if it is not an auth collection or the record is not found.
	FindAuthRecordByEmail(collectionModelOrIdentifier any, email string) (*Record, error)

	// CanAccessRecord checks if a record is allowed to be accessed by the
	// specified requestInfo and accessRule.
	//
	// Rule and db checks are ignored in case the requestInfo actor has the record collection "view" bypass permission (e.g. Owners; see [Authorize]).
	//
	// The returned error indicate that something unexpected happened during
	// the check (eg. invalid rule or db query error).
	//
	// The method always return false on invalid rule or db query error.
	//
	// Example:
	//
	//	requestInfo, _ := e.RequestInfo()
	//	record, _ := app.FindRecordById("example", "RECORD_ID")
	//	rule := types.Pointer("@request.auth.id != '' || status = 'public'")
	//	// ... or use one of the record collection's rule, eg. record.Collection().ViewRule
	//
	//	if ok, _ := app.CanAccessRecord(record, requestInfo, rule); ok { ... }
	CanAccessRecord(record *Record, requestInfo *RequestInfo, accessRule *string) (bool, error)

	// ExpandRecord expands the relations of a single Record model.
	//
	// If optFetchFunc is not set, then a default function will be used
	// that returns all relation records.
	//
	// Returns a map with the failed expand parameters and their errors.
	ExpandRecord(record *Record, expands []string, optFetchFunc ExpandFetchFunc) map[string]error

	// ExpandRecords expands the relations of the provided Record models list.
	//
	// If optFetchFunc is not set, then a default function will be used
	// that returns all relation records.
	//
	// Returns a map with the failed expand parameters and their errors.
	ExpandRecords(records []*Record, expands []string, optFetchFunc ExpandFetchFunc) map[string]error

	// ---------------------------------------------------------------
	// App event hooks
	// ---------------------------------------------------------------

	// OnBootstrap hook is triggered when initializing the main application
	// resources (db, app settings, etc).
	OnBootstrap() *hook.Hook[*BootstrapEvent]

	// OnBootstrapClear hook is triggered when clearing the main application
	// resources (db connections, cron, logger, etc.)
	//
	// It is usually invoked automatically right before app termination
	// or when manually calling app.ClearBootstrap().
	OnBootstrapClear() *hook.Hook[*BootstrapEvent]

	// OnServe hook is triggered when the app web server is started
	// (after starting the TCP listener but before initializing the blocking serve task),
	// allowing you to adjust its options and attach new routes or middlewares.
	OnServe() *hook.Hook[*ServeEvent]

	// OnTerminate hook is triggered when the app is in the process
	// of being terminated (ex. on SIGTERM signal).
	//
	// Note that the app could be terminated abruptly without awaiting the hook completion.
	OnTerminate() *hook.Hook[*TerminateEvent]

	// OnBackupCreate hook is triggered on each [App.CreateBackup] call.
	OnBackupCreate() *hook.Hook[*BackupEvent]

	// OnBackupRestore hook is triggered before app backup restore (aka. [App.RestoreBackup] call).
	//
	// Note that by default on success the application is restarted and the after state of the hook is ignored.
	OnBackupRestore() *hook.Hook[*BackupEvent]

	// ---------------------------------------------------------------
	// DB models event hooks
	// ---------------------------------------------------------------

	// OnModelValidate is triggered every time when a model is being validated
	// (e.g. triggered by App.Validate() or App.Save()).
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelValidate(tags ...string) *hook.TaggedHook[*ModelEvent]

	// ---------------------------------------------------------------

	// OnModelCreate is triggered every time when a new model is being created
	// (e.g. triggered by App.Save()).
	//
	// Operations BEFORE the e.Next() execute before the model validation
	// and the INSERT DB statement.
	//
	// Operations AFTER the e.Next() execute after the model validation
	// and the INSERT DB statement.
	//
	// Note that successful execution doesn't guarantee that the model
	// is persisted in the database since its wrapping transaction may
	// not have been committed yet.
	// If you want to listen to only the actual persisted events, you can
	// bind to [OnModelAfterCreateSuccess] or [OnModelAfterCreateError] hooks.
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelCreate(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelCreateExecute is triggered after successful Model validation
	// and right before the model INSERT DB statement execution.
	//
	// Usually it is triggered as part of the App.Save() in the following firing order:
	// OnModelCreate {
	//    -> OnModelValidate (skipped with App.SaveNoValidate())
	//    -> OnModelCreateExecute
	// }
	//
	// Note that successful execution doesn't guarantee that the model
	// is persisted in the database since its wrapping transaction may have been
	// committed yet.
	// If you want to listen to only the actual persisted events,
	// you can bind to [OnModelAfterCreateSuccess] or [OnModelAfterCreateError] hooks.
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelCreateExecute(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelAfterCreateSuccess is triggered after each successful
	// Model DB create persistence.
	//
	// Note that when a Model is persisted as part of a transaction,
	// this hook is delayed and executed only AFTER the transaction has been committed.
	// This hook is NOT triggered in case the transaction rollbacks
	// (aka. when the model wasn't persisted).
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelAfterCreateSuccess(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelAfterCreateError is triggered after each failed
	// Model DB create persistence.
	//
	// Note that the execution of this hook is either immediate or delayed
	// depending on the error:
	//   - "immediate" on App.Save() failure
	//   - "delayed" on transaction rollback
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelAfterCreateError(tags ...string) *hook.TaggedHook[*ModelErrorEvent]

	// ---------------------------------------------------------------

	// OnModelUpdate is triggered every time when a new model is being updated
	// (e.g. triggered by App.Save()).
	//
	// Operations BEFORE the e.Next() execute before the model validation
	// and the UPDATE DB statement.
	//
	// Operations AFTER the e.Next() execute after the model validation
	// and the UPDATE DB statement.
	//
	// Note that successful execution doesn't guarantee that the model
	// is persisted in the database since its wrapping transaction may
	// not have been committed yet.
	// If you want to listen to only the actual persisted events, you can
	// bind to [OnModelAfterUpdateSuccess] or [OnModelAfterUpdateError] hooks.
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelUpdate(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelUpdateExecute is triggered after successful Model validation
	// and right before the model UPDATE DB statement execution.
	//
	// Usually it is triggered as part of the App.Save() in the following firing order:
	// OnModelUpdate {
	//    -> OnModelValidate (skipped with App.SaveNoValidate())
	//    -> OnModelUpdateExecute
	// }
	//
	// Note that successful execution doesn't guarantee that the model
	// is persisted in the database since its wrapping transaction may have been
	// committed yet.
	// If you want to listen to only the actual persisted events,
	// you can bind to [OnModelAfterUpdateSuccess] or [OnModelAfterUpdateError] hooks.
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelUpdateExecute(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelAfterUpdateSuccess is triggered after each successful
	// Model DB update persistence.
	//
	// Note that when a Model is persisted as part of a transaction,
	// this hook is delayed and executed only AFTER the transaction has been committed.
	// This hook is NOT triggered in case the transaction rollbacks
	// (aka. when the model changes weren't persisted).
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelAfterUpdateSuccess(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelAfterUpdateError is triggered after each failed
	// Model DB update persistence.
	//
	// Note that the execution of this hook is either immediate or delayed
	// depending on the error:
	//   - "immediate" on App.Save() failure
	//   - "delayed" on transaction rollback
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelAfterUpdateError(tags ...string) *hook.TaggedHook[*ModelErrorEvent]

	// ---------------------------------------------------------------

	// OnModelDelete is triggered every time when a new model is being deleted
	// (e.g. triggered by App.Delete()).
	//
	// Note that successful execution doesn't guarantee that the model
	// is deleted from the database since its wrapping transaction may
	// not have been committed yet.
	// If you want to listen to only the actual persisted deleted events, you can
	// bind to [OnModelAfterDeleteSuccess] or [OnModelAfterDeleteError] hooks.
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelDelete(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelUpdateExecute is triggered right before the model
	// DELETE DB statement execution.
	//
	// Usually it is triggered as part of the App.Delete() in the following firing order:
	// OnModelDelete {
	//    -> (internal delete checks)
	//    -> OnModelDeleteExecute
	// }
	//
	// Note that successful execution doesn't guarantee that the model
	// is deleted from the database since its wrapping transaction may
	// not have been committed yet.
	// If you want to listen to only the actual persisted deleted events, you can
	// bind to [OnModelAfterDeleteSuccess] or [OnModelAfterDeleteError] hooks.
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelDeleteExecute(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelAfterDeleteSuccess is triggered after each successful
	// Model DB delete persistence.
	//
	// Note that when a Model is deleted as part of a transaction,
	// this hook is delayed and executed only AFTER the transaction has been committed.
	// This hook is NOT triggered in case the transaction rollbacks
	// (aka. when the model delete wasn't persisted).
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelAfterDeleteSuccess(tags ...string) *hook.TaggedHook[*ModelEvent]

	// OnModelAfterDeleteError is triggered after each failed
	// Model DB delete persistence.
	//
	// Note that the execution of this hook is either immediate or delayed
	// depending on the error:
	//   - "immediate" on App.Delete() failure
	//   - "delayed" on transaction rollback
	//
	// For convenience, if you want to listen to only the Record models
	// events without doing manual type assertion, you can attach to the OnRecord* proxy hooks.
	//
	// If the optional "tags" list (Collection id/name, Model table name, etc.) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnModelAfterDeleteError(tags ...string) *hook.TaggedHook[*ModelErrorEvent]

	// ---------------------------------------------------------------
	// Record models event hooks
	// ---------------------------------------------------------------

	// OnRecordEnrich is triggered every time when a record is enriched
	// (as part of the builtin Record responses, during realtime message seriazation, or when [apis.EnrichRecord] is invoked).
	//
	// It could be used for example to redact/hide or add computed temporary
	// Record model props only for the specific request info. For example:
	//
	//  app.OnRecordEnrich("posts").BindFunc(func(e core.*RecordEnrichEvent) {
	//      // hide one or more fields
	//      e.Record.Hide("role")
	//
	//      // add new custom field for registered users
	//      if e.RequestInfo.Auth != nil && e.RequestInfo.Auth.Collection().Name == "users" {
	//          e.Record.WithCustomData(true) // for security requires explicitly allowing it
	//          e.Record.Set("computedScore", e.Record.GetInt("score") * e.RequestInfo.Auth.GetInt("baseScore"))
	//      }
	//
	//      return e.Next()
	//  })
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordEnrich(tags ...string) *hook.TaggedHook[*RecordEnrichEvent]

	// OnRecordValidate is a Record proxy model hook of [OnModelValidate].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordValidate(tags ...string) *hook.TaggedHook[*RecordEvent]

	// ---------------------------------------------------------------

	// OnRecordCreate is a Record proxy model hook of [OnModelCreate].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordCreate(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordCreateExecute is a Record proxy model hook of [OnModelCreateExecute].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordCreateExecute(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordAfterCreateSuccess is a Record proxy model hook of [OnModelAfterCreateSuccess].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordAfterCreateSuccess(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordAfterCreateError is a Record proxy model hook of [OnModelAfterCreateError].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordAfterCreateError(tags ...string) *hook.TaggedHook[*RecordErrorEvent]

	// ---------------------------------------------------------------

	// OnRecordUpdate is a Record proxy model hook of [OnModelUpdate].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordUpdate(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordUpdateExecute is a Record proxy model hook of [OnModelUpdateExecute].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordUpdateExecute(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordAfterUpdateSuccess is a Record proxy model hook of [OnModelAfterUpdateSuccess].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordAfterUpdateSuccess(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordAfterUpdateError is a Record proxy model hook of [OnModelAfterUpdateError].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordAfterUpdateError(tags ...string) *hook.TaggedHook[*RecordErrorEvent]

	// ---------------------------------------------------------------

	// OnRecordDelete is a Record proxy model hook of [OnModelDelete].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordDelete(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordDeleteExecute is a Record proxy model hook of [OnModelDeleteExecute].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordDeleteExecute(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordAfterDeleteSuccess is a Record proxy model hook of [OnModelAfterDeleteSuccess].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordAfterDeleteSuccess(tags ...string) *hook.TaggedHook[*RecordEvent]

	// OnRecordAfterDeleteError is a Record proxy model hook of [OnModelAfterDeleteError].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordAfterDeleteError(tags ...string) *hook.TaggedHook[*RecordErrorEvent]

	// ---------------------------------------------------------------
	// Collection models event hooks
	// ---------------------------------------------------------------

	// OnCollectionValidate is a Collection proxy model hook of [OnModelValidate].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionValidate(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// ---------------------------------------------------------------

	// OnCollectionCreate is a Collection proxy model hook of [OnModelCreate].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionCreate(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionCreateExecute is a Collection proxy model hook of [OnModelCreateExecute].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionCreateExecute(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionAfterCreateSuccess is a Collection proxy model hook of [OnModelAfterCreateSuccess].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionAfterCreateSuccess(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionAfterCreateError is a Collection proxy model hook of [OnModelAfterCreateError].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionAfterCreateError(tags ...string) *hook.TaggedHook[*CollectionErrorEvent]

	// ---------------------------------------------------------------

	// OnCollectionUpdate is a Collection proxy model hook of [OnModelUpdate].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionUpdate(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionUpdateExecute is a Collection proxy model hook of [OnModelUpdateExecute].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionUpdateExecute(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionAfterUpdateSuccess is a Collection proxy model hook of [OnModelAfterUpdateSuccess].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionAfterUpdateSuccess(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionAfterUpdateError is a Collection proxy model hook of [OnModelAfterUpdateError].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionAfterUpdateError(tags ...string) *hook.TaggedHook[*CollectionErrorEvent]

	// ---------------------------------------------------------------

	// OnCollectionDelete is a Collection proxy model hook of [OnModelDelete].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionDelete(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionDeleteExecute is a Collection proxy model hook of [OnModelDeleteExecute].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionDeleteExecute(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionAfterDeleteSuccess is a Collection proxy model hook of [OnModelAfterDeleteSuccess].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionAfterDeleteSuccess(tags ...string) *hook.TaggedHook[*CollectionEvent]

	// OnCollectionAfterDeleteError is a Collection proxy model hook of [OnModelAfterDeleteError].
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnCollectionAfterDeleteError(tags ...string) *hook.TaggedHook[*CollectionErrorEvent]

	// ---------------------------------------------------------------
	// Mailer event hooks
	// ---------------------------------------------------------------

	// OnMailerSend hook is triggered every time when a new email is
	// being sent using the [App.NewMailClient()] instance.
	//
	// It allows intercepting the email message or to use a custom mailer client.
	OnMailerSend() *hook.Hook[*MailerEvent]

	// OnMailerRecordAuthAlertSend hook is triggered when
	// sending a new device login auth alert email, allowing you to
	// intercept and customize the email message that is being sent.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnMailerRecordAuthAlertSend(tags ...string) *hook.TaggedHook[*MailerRecordEvent]

	// OnMailerBeforeRecordResetPasswordSend hook is triggered when
	// sending a password reset email to an auth record, allowing
	// you to intercept and customize the email message that is being sent.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnMailerRecordPasswordResetSend(tags ...string) *hook.TaggedHook[*MailerRecordEvent]

	// OnMailerBeforeRecordVerificationSend hook is triggered when
	// sending a verification email to an auth record, allowing
	// you to intercept and customize the email message that is being sent.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnMailerRecordVerificationSend(tags ...string) *hook.TaggedHook[*MailerRecordEvent]

	// OnMailerRecordEmailChangeSend hook is triggered when sending a
	// confirmation new address email to an auth record, allowing
	// you to intercept and customize the email message that is being sent.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnMailerRecordEmailChangeSend(tags ...string) *hook.TaggedHook[*MailerRecordEvent]

	// OnMailerRecordOTPSend hook is triggered when sending an OTP email
	// to an auth record, allowing you to intercept and customize the
	// email message that is being sent.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnMailerRecordOTPSend(tags ...string) *hook.TaggedHook[*MailerRecordEvent]

	// ---------------------------------------------------------------
	// Filesystem event hooks
	// (not publicly exposed until file_field refactoring)
	// ---------------------------------------------------------------

	// onFilesystemNewWriter is an internal hook for app.NewFilesystem()
	// instances that is triggered on every storage filesystem writer initialization
	// (aka. whenever attempting to create a new file).
	onFilesystemNewWriter() *hook.Hook[*FilesystemNewWriterEvent]

	// onFilesystemDelete is an internal hook for app.NewFilesystem()
	// instances that is triggered for every storage file delete call.
	onFilesystemDelete() *hook.Hook[*FilesystemDeleteEvent]

	// ---------------------------------------------------------------
	// Realtime API event hooks
	// ---------------------------------------------------------------

	// OnRealtimeConnectRequest hook is triggered when establishing the SSE client connection.
	//
	// Any execution after e.Next() of a hook handler happens after the client disconnects.
	OnRealtimeConnectRequest() *hook.Hook[*RealtimeConnectRequestEvent]

	// OnRealtimeMessageSend hook is triggered when sending an SSE message to a client.
	OnRealtimeMessageSend() *hook.Hook[*RealtimeMessageEvent]

	// OnRealtimeSubscribeRequest hook is triggered when updating the
	// client subscriptions, allowing you to further validate and
	// modify the submitted change.
	OnRealtimeSubscribeRequest() *hook.Hook[*RealtimeSubscribeRequestEvent]

	// ---------------------------------------------------------------
	// Settings API event hooks
	// ---------------------------------------------------------------

	// OnSettingsListRequest hook is triggered on each API Settings list request.
	//
	// Could be used to validate or modify the response before returning it to the client.
	OnSettingsListRequest() *hook.Hook[*SettingsListRequestEvent]

	// OnSettingsUpdateRequest hook is triggered on each API Settings update request.
	//
	// Could be used to additionally validate the request data or
	// implement completely different persistence behavior.
	OnSettingsUpdateRequest() *hook.Hook[*SettingsUpdateRequestEvent]

	// OnSettingsReload hook is triggered every time when the App.Settings()
	// is being replaced with a new state.
	//
	// Calling App.Settings() after e.Next() returns the new state.
	OnSettingsReload() *hook.Hook[*SettingsReloadEvent]

	// ---------------------------------------------------------------
	// File API event hooks
	// ---------------------------------------------------------------

	// OnFileDownloadRequest hook is triggered before each API File download request.
	//
	// Could be used to validate or modify the file response before
	// returning it to the client.
	OnFileDownloadRequest(tags ...string) *hook.TaggedHook[*FileDownloadRequestEvent]

	// OnFileBeforeTokenRequest hook is triggered on each auth file token API request.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnFileTokenRequest(tags ...string) *hook.TaggedHook[*FileTokenRequestEvent]

	// ---------------------------------------------------------------
	// Record account API event hooks
	// (triggered by the actor APIs and the OAuth2 server hosted account pages)
	// ---------------------------------------------------------------

	// OnRecordRequestPasswordResetRequest hook is triggered on
	// each Record request password reset API request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different password reset behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordRequestPasswordResetRequest(tags ...string) *hook.TaggedHook[*RecordRequestPasswordResetRequestEvent]

	// OnRecordConfirmPasswordResetRequest hook is triggered on
	// each Record confirm password reset API request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordConfirmPasswordResetRequest(tags ...string) *hook.TaggedHook[*RecordConfirmPasswordResetRequestEvent]

	// OnRecordRequestVerificationRequest hook is triggered on
	// each Record request verification API request.
	//
	// Could be used to additionally validate the loaded request data or implement
	// completely different verification behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordRequestVerificationRequest(tags ...string) *hook.TaggedHook[*RecordRequestVerificationRequestEvent]

	// OnRecordConfirmVerificationRequest hook is triggered on each
	// Record confirm verification API request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordConfirmVerificationRequest(tags ...string) *hook.TaggedHook[*RecordConfirmVerificationRequestEvent]

	// OnRecordRequestEmailChangeRequest hook is triggered on each
	// Record request email change API request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different request email change behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordRequestEmailChangeRequest(tags ...string) *hook.TaggedHook[*RecordRequestEmailChangeRequestEvent]

	// OnRecordConfirmEmailChangeRequest hook is triggered on each
	// Record confirm email change API request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordConfirmEmailChangeRequest(tags ...string) *hook.TaggedHook[*RecordConfirmEmailChangeRequestEvent]

	// ---------------------------------------------------------------
	// Record CRUD API event hooks
	// ---------------------------------------------------------------

	// OnRecordsListRequest hook is triggered on each API Records list request.
	//
	// Could be used to validate or modify the response before returning it to the client.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordsListRequest(tags ...string) *hook.TaggedHook[*RecordsListRequestEvent]

	// OnRecordViewRequest hook is triggered on each API Record view request.
	//
	// Could be used to validate or modify the response before returning it to the client.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordViewRequest(tags ...string) *hook.TaggedHook[*RecordRequestEvent]

	// OnRecordCreateRequest hook is triggered on each API Record create request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordCreateRequest(tags ...string) *hook.TaggedHook[*RecordRequestEvent]

	// OnRecordUpdateRequest hook is triggered on each API Record update request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordUpdateRequest(tags ...string) *hook.TaggedHook[*RecordRequestEvent]

	// OnRecordDeleteRequest hook is triggered on each API Record delete request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different delete behavior.
	//
	// If the optional "tags" list (Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnRecordDeleteRequest(tags ...string) *hook.TaggedHook[*RecordRequestEvent]

	// ---------------------------------------------------------------
	// Collection API event hooks
	// ---------------------------------------------------------------

	// OnCollectionsListRequest hook is triggered on each API Collections list request.
	//
	// Could be used to validate or modify the response before returning it to the client.
	OnCollectionsListRequest() *hook.Hook[*CollectionsListRequestEvent]

	// OnCollectionViewRequest hook is triggered on each API Collection view request.
	//
	// Could be used to validate or modify the response before returning it to the client.
	OnCollectionViewRequest() *hook.Hook[*CollectionRequestEvent]

	// OnCollectionCreateRequest hook is triggered on each API Collection create request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	OnCollectionCreateRequest() *hook.Hook[*CollectionRequestEvent]

	// OnCollectionUpdateRequest hook is triggered on each API Collection update request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different persistence behavior.
	OnCollectionUpdateRequest() *hook.Hook[*CollectionRequestEvent]

	// OnCollectionDeleteRequest hook is triggered on each API Collection delete request.
	//
	// Could be used to additionally validate the request data or implement
	// completely different delete behavior.
	OnCollectionDeleteRequest() *hook.Hook[*CollectionRequestEvent]

	// OnCollectionsBeforeImportRequest hook is triggered on each API
	// collections import request.
	//
	// Could be used to additionally validate the imported collections or
	// to implement completely different import behavior.
	OnCollectionsImportRequest() *hook.Hook[*CollectionsImportRequestEvent]

	// ---------------------------------------------------------------
	// Batch API event hooks
	// ---------------------------------------------------------------

	// OnBatchRequest hook is triggered on each API batch request.
	//
	// Could be used to additionally validate or modify the submitted batch requests.
	OnBatchRequest() *hook.Hook[*BatchRequestEvent]

	// ---------------------------------------------------------------
	// GraphQL API event hooks
	// ---------------------------------------------------------------

	// OnGraphQLRequest hook is triggered on each API GraphQL request
	// (after the request payload is parsed and before the query is executed).
	//
	// Could be used to additionally validate or modify the submitted query
	// or to respond with a custom result without calling e.Next().
	OnGraphQLRequest() *hook.Hook[*GraphQLRequestEvent]

	// ---------------------------------------------------------------
	// OAuth2 server (aka. OpenID Connect provider) API event hooks
	// ---------------------------------------------------------------

	// OnAuthSessionStepRequest hook is triggered on each completed auth session factor
	// (password, otp, oauth2 or custom) of the hosted login flow,
	// right before the factor is registered in the session.
	//
	// Could be used to reject the factor (by returning an error)
	// or to alter the factor data (e.g. the identified record).
	//
	// If the optional "tags" list (auth Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnAuthSessionStepRequest(tags ...string) *hook.TaggedHook[*AuthSessionStepRequestEvent]

	// OnAuthSessionCompleteRequest hook is triggered when an auth session completes
	// its authentication (all required factors incl. MFA are satisfied and the
	// AuthRule passed or a root SSO session was reused), right before
	// the consent and authorization code steps.
	//
	// Could be used to reject the authentication (by returning an error)
	// or to reduce the granted scopes.
	//
	// Note that it cannot add token claims - the extra id_token claims
	// should be added with the [App.OnOAuth2TokenRequest] hook
	// (see [OAuth2TokenRequestEvent.IdTokenClaims]).
	//
	// If the optional "tags" list (auth Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnAuthSessionCompleteRequest(tags ...string) *hook.TaggedHook[*AuthSessionCompleteRequestEvent]

	// OnOAuth2AuthorizeRequest hook is triggered on each successful OAuth2 server
	// authorization request (right before issuing the authorization code
	// and redirecting back to the client).
	//
	// Could be used to additionally validate the authorization request
	// (e.g. to restrict the client access for specific auth records).
	//
	// If the optional "tags" list (auth Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnOAuth2AuthorizeRequest(tags ...string) *hook.TaggedHook[*OAuth2AuthorizeRequestEvent]

	// OnOAuth2TokenRequest hook is triggered on each OAuth2 server token request
	// (authorization code exchange, refresh token rotation or token exchange)
	// right before generating the access, refresh and id tokens.
	//
	// Could be used to additionally validate the request or to add
	// custom id_token claims (see [OAuth2TokenRequestEvent.IdTokenClaims]).
	//
	// If the optional "tags" list (auth Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnOAuth2TokenRequest(tags ...string) *hook.TaggedHook[*OAuth2TokenRequestEvent]

	// OnOAuth2RevokeRequest hook is triggered on each OAuth2 server token
	// revocation request (right before ending the related auth session).
	//
	// If the optional "tags" list (auth Collection ids or names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnOAuth2RevokeRequest(tags ...string) *hook.TaggedHook[*OAuth2RevokeRequestEvent]

	// ---------------------------------------------------------------
	// Applications event hooks
	// ---------------------------------------------------------------

	// OnApplicationManifestImport hook is triggered on each application manifest import
	// (custom and catalog) right before the application and its version are stored.
	OnApplicationManifestImport() *hook.Hook[*ApplicationManifestImportEvent]

	// OnApplicationInstall hook is triggered on each [App.InstallApplication] call.
	OnApplicationInstall() *hook.Hook[*ApplicationInstallEvent]

	// OnApplicationInstallationUpdate hook is triggered on each [App.UpdateApplicationInstallation] call.
	OnApplicationInstallationUpdate() *hook.Hook[*ApplicationInstallationUpdateEvent]

	// OnApplicationSecretRotate hook is triggered on each [App.RotateApplicationInstallationSecret] call.
	OnApplicationSecretRotate() *hook.Hook[*ApplicationSecretRotateEvent]

	// OnApplicationUninstall hook is triggered on each [App.UninstallApplication] call.
	OnApplicationUninstall() *hook.Hook[*ApplicationUninstallEvent]

	// OnApplicationManifestImportRequest hook is triggered on each application manifest
	// import request (POST /api/applications/manifests and the create custom application
	// form POST /api/applications) after the manifest was parsed and validated
	// and right before it is stored.
	//
	// Could be used to additionally validate or reject the manifest.
	OnApplicationManifestImportRequest() *hook.Hook[*ApplicationManifestImportRequestEvent]

	// OnApplicationInstallRequest hook is triggered on each application install request
	// right before the installation and its managed OAuth2 client are created.
	//
	// Could be used to additionally validate or reject the installation grant.
	OnApplicationInstallRequest() *hook.Hook[*ApplicationInstallRequestEvent]

	// OnApplicationUninstallRequest hook is triggered on each application uninstall
	// request right before the installation (and its managed client and sessions) is deleted.
	OnApplicationUninstallRequest() *hook.Hook[*ApplicationUninstallRequestEvent]

	// ---------------------------------------------------------------
	// LLM event hooks
	// ---------------------------------------------------------------

	// OnLLMRequest hook is triggered before every [App.NewLLMClient]
	// client Generate and Stream call (after the profile defaults are applied).
	//
	// Could be used to modify the request (e.g. redact messages) or
	// to abort it by returning an error (the aborted requests are logged as "denied").
	//
	// If the optional "tags" list (LLM profile or provider names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnLLMRequest(tags ...string) *hook.TaggedHook[*LLMRequestEvent]

	// OnLLMResponse hook is triggered after every [App.NewLLMClient]
	// client Generate and Stream call (including the failed ones).
	//
	// For streams it is triggered once the stream ends with the accumulated response.
	//
	// Could be used to inspect the tokens usage or to modify the response/error
	// before it is logged and returned to the caller.
	//
	// If the optional "tags" list (LLM profile or provider names) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnLLMResponse(tags ...string) *hook.TaggedHook[*LLMResponseEvent]

	// ---------------------------------------------------------------
	// Webhooks event hooks
	// ---------------------------------------------------------------

	// OnWebhookSend hook is triggered before each webhook delivery attempt
	// (including the test sends).
	//
	// Could be used to modify the request headers and body (the signature is
	// calculated from the final body), to skip the delivery by not calling
	// e.Next() (the delivery is marked as "disabled") or to fail the
	// attempt by returning an error (the delivery is retried).
	//
	// If the optional "tags" list (webhook subscription ids or topics) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnWebhookSend(tags ...string) *hook.TaggedHook[*WebhookSendEvent]

	// OnWebhookDelivery hook is triggered after each processed webhook
	// delivery attempt with its result (the delivery state is already persisted).
	//
	// If the optional "tags" list (webhook subscription ids or topics) is specified,
	// then all event handlers registered via the created hook will be
	// triggered and called only if their event data origin matches the tags.
	OnWebhookDelivery(tags ...string) *hook.TaggedHook[*WebhookDeliveryEvent]
}
