package apis

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/auth"
	"github.com/lumm2509/pocketbomb/tools/dbutils"
	"github.com/lumm2509/pocketbomb/tools/filesystem"
	"github.com/lumm2509/pocketbomb/tools/inflector"
	"github.com/lumm2509/pocketbomb/tools/safehttp"
	"github.com/pocketbase/dbx"
)

// Upstream (federated) OAuth2 login record helpers
// -------------------------------------------------------------------

// @todo evaluate if it is still worth keeping as this exists only for backward-compatibility with pre v0.23 versions
func oldCanAssignUsername(txApp core.App, collection *core.Collection, username string) bool {
	field := collection.Fields.GetByName(collection.OAuth2.MappedFields.Username)
	if field == nil {
		return false
	}

	// ensure that the value matches the pattern of the username field (if text)
	if txtField, ok := field.(*core.TextField); ok && txtField.ValidatePlainValue(username) != nil {
		return false
	}

	// ensure that username is unique
	index, hasUniqueue := dbutils.FindSingleColumnUniqueIndex(collection.Indexes, field.GetName())
	if hasUniqueue {
		// it is not required because collection fields are already sanitized
		// but normalize as an extra precaution in case of a custom validator
		colName := inflector.Columnify(field.GetName())

		var expr dbx.Expression
		if strings.EqualFold(index.Columns[0].Collate, "nocase") {
			// case-insensitive search
			expr = dbx.NewExp("[["+colName+"]] = {:username} COLLATE NOCASE", dbx.Params{"username": username})
		} else {
			expr = dbx.HashExp{colName: username}
		}

		var exists int
		_ = txApp.RecordQuery(collection).Select("(1)").AndWhere(expr).Limit(1).Row(&exists)
		if exists > 0 {
			return false
		}
	}

	return true
}

// findOAuth2UpstreamRecord looks for the auth record of the provided upstream OAuth2 user:
//   - by an existing external auth relation
//   - or by the OAuth2 user email
//
// Returns nil record if there is no matching record (aka. a new record should be created).
//
// Note that there is no "link to the currently authenticated record" fallback because
// a (partially authenticated) hosted login flow must never link new providers.
func findOAuth2UpstreamRecord(
	app core.App,
	collection *core.Collection,
	providerName string,
	authUser *auth.AuthUser,
) (*core.Record, *core.ExternalAuth, error) {
	// check for existing relation with the auth collection
	externalAuthRel, err := app.FindFirstExternalAuthByExpr(dbx.HashExp{
		"collectionRef": collection.Id,
		"provider":      providerName,
		"providerId":    authUser.Id,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}

	switch {
	case err == nil && externalAuthRel != nil:
		authRecord, err := app.FindRecordById(collection, externalAuthRel.RecordRef())
		if err != nil {
			return nil, nil, err
		}
		return authRecord, externalAuthRel, nil
	case authUser.Email != "":
		// look for an existing auth record by the external auth record's email
		authRecord, err := app.FindAuthRecordByEmail(collection.Id, authUser.Email)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, err
		}
		return authRecord, nil, nil
	}

	return nil, nil, nil
}

// saveOAuth2UpstreamRecord creates (if record is nil) or updates the auth record
// of the provided upstream OAuth2 user (field mappings, verified state,
// pre-hijacking protections) and links the external auth relation if missing.
//
// The new records are created through the regular record create API
// (aka. the collection create rule, hooks and validations apply).
func saveOAuth2UpstreamRecord(
	ctx context.Context,
	e *core.RequestEvent,
	collection *core.Collection,
	providerName string,
	oauth2User *auth.AuthUser,
	createData map[string]any,
	record *core.Record,
	optExternalAuth *core.ExternalAuth,
) (*core.Record, error) {
	err := e.App.RunInTransaction(func(txApp core.App) error {
		if record == nil {
			// extra check to prevent creating a superuser record via
			// OAuth2 in case the method is used by another action
			if collection.Name == core.CollectionNameSuperusers {
				return errors.New("superusers are not allowed to sign-up with OAuth2")
			}

			payload := maps.Clone(createData)
			if payload == nil {
				payload = map[string]any{}
			}

			// assign the OAuth2 user email only if the user hasn't submitted one
			// (ignore empty/invalid values for consistency with the OAuth2->existing user update flow)
			if v, _ := payload[core.FieldNameEmail].(string); v == "" {
				payload[core.FieldNameEmail] = oauth2User.Email
			}

			// map known fields (unless the field was explicitly submitted as part of CreateData)
			if _, ok := payload[collection.OAuth2.MappedFields.Id]; !ok && collection.OAuth2.MappedFields.Id != "" {
				payload[collection.OAuth2.MappedFields.Id] = oauth2User.Id
			}
			if _, ok := payload[collection.OAuth2.MappedFields.Name]; !ok && collection.OAuth2.MappedFields.Name != "" {
				payload[collection.OAuth2.MappedFields.Name] = oauth2User.Name
			}
			if _, ok := payload[collection.OAuth2.MappedFields.Username]; !ok &&
				// no explicit username payload value and existing OAuth2 mapping
				collection.OAuth2.MappedFields.Username != "" &&
				// extra checks for backward compatibility with earlier versions
				oldCanAssignUsername(txApp, collection, oauth2User.Username) {
				payload[collection.OAuth2.MappedFields.Username] = oauth2User.Username
			}
			if _, ok := payload[collection.OAuth2.MappedFields.AvatarURL]; !ok &&
				// no explicit avatar payload value and existing OAuth2 mapping
				collection.OAuth2.MappedFields.AvatarURL != "" &&
				// non-empty OAuth2 avatar url
				oauth2User.AvatarURL != "" {
				mappedField := collection.Fields.GetByName(collection.OAuth2.MappedFields.AvatarURL)
				if mappedField != nil && mappedField.Type() == core.FieldTypeFile {
					// download the avatar if the mapped field is a file
					avatarFile, err := func() (*filesystem.File, error) {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()

						// the extra checks are not required because the OAuth2 APIs are trusted vendor
						// but are here to minimize the impact in case the provider is vulnerable
						return safeFileFromURL(ctx, oauth2User.AvatarURL)
					}()
					if err != nil {
						txApp.Logger().Warn("Failed to retrieve OAuth2 avatar", slog.String("error", err.Error()))
					} else {
						payload[collection.OAuth2.MappedFields.AvatarURL] = avatarFile
					}
				} else {
					// otherwise - assign the url string
					payload[collection.OAuth2.MappedFields.AvatarURL] = oauth2User.AvatarURL
				}
			}

			createdRecord, err := sendOAuth2RecordCreateRequest(txApp, e, collection, payload)
			if err != nil {
				return err
			}

			record = createdRecord

			if record.Email() == oauth2User.Email && !record.Verified() {
				// mark as verified as long as it matches the OAuth2 data (even if the email is empty)
				record.SetVerified(true)
				if err := txApp.SaveWithContext(ctx, record); err != nil {
					return err
				}
			}
		} else {
			var needUpdate bool

			isLoggedAuthRecord := e.Auth != nil &&
				e.Auth.Id == record.Id &&
				e.Auth.Collection().Id == record.Collection().Id

			// prevent pre-hijacking with password auth
			//
			// reset the unverified user password in case the record was precreated by a malicious actor
			if !isLoggedAuthRecord && !record.Verified() {
				needUpdate = true
				record.SetRandomPassword()
			}

			// prevent pre-hijacking with different OAuth2 provider
			//
			// delete all other previous OAuth2 record links for the cases
			// when the user was precreated by malicious OAuth2 auth with custom payload data
			//
			// while this would be also done automatically on unverified -> verified upgrade,
			// doing it manually here ensures that a single unverified record could have
			// max 1 OAuth2 link to prevent further abuse when mixed with other auth flows
			if !record.Verified() {
				err := txApp.DeleteAllExternalAuthsByRecord(record)
				if err != nil {
					return err
				}
				optExternalAuth = nil // clear to allow recreate below
			}

			// update the existing auth record empty email if the data.OAuth2User has one
			// (this is in case previously the auth record was created
			// with an OAuth2 provider that didn't return an email address)
			if record.Email() == "" && oauth2User.Email != "" {
				needUpdate = true
				record.SetEmail(oauth2User.Email)
			}

			// update the existing auth record verified state
			// (only if the auth record doesn't have an email or the auth record email match with the one in data.OAuth2User)
			if !record.Verified() && (record.Email() == "" || record.Email() == oauth2User.Email) {
				needUpdate = true
				record.SetVerified(true)
			}

			if needUpdate {
				if err := txApp.SaveWithContext(ctx, record); err != nil {
					return err
				}
			}
		}

		// create ExternalAuth relation if missing
		if optExternalAuth == nil {
			optExternalAuth = core.NewExternalAuth(txApp)
			optExternalAuth.SetCollectionRef(record.Collection().Id)
			optExternalAuth.SetRecordRef(record.Id)
			optExternalAuth.SetProvider(providerName)
			optExternalAuth.SetProviderId(oauth2User.Id)

			if err := txApp.Save(optExternalAuth); err != nil {
				return fmt.Errorf("failed to save linked rel: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return record, nil
}

func sendOAuth2RecordCreateRequest(txApp core.App, e *core.RequestEvent, collection *core.Collection, payload map[string]any) (*core.Record, error) {
	ir := &core.InternalRequest{
		Method: http.MethodPost,
		URL:    "/api/collections/" + collection.Name + "/records",
		Body:   payload,
	}

	var createdRecord *core.Record
	response, err := processInternalRequest(txApp, e, ir, core.RequestInfoContextOAuth2, func(data any) error {
		createdRecord, _ = data.(*core.Record)

		return nil
	})
	if err != nil {
		return nil, err
	}

	if response.Status != http.StatusOK || createdRecord == nil {
		return nil, errors.New("failed to create OAuth2 auth record")
	}

	return createdRecord, nil
}

// -------------------------------------------------------------------

// safeFileFromURL downloads the file from the specified url with the SSRF
// protected client and creates a new filesystem.File value from its content
// (limited to DefaultMaxBodySize).
func safeFileFromURL(ctx context.Context, url string) (*filesystem.File, error) {
	client := safehttp.NewClient(safehttp.Options{Timeout: 180 * time.Second})

	res, err := client.Fetch(ctx, url, safehttp.FetchOptions{
		MaxBodySize:             DefaultMaxBodySize,
		MaxRedirects:            10,
		AllowCrossHostRedirects: true,
	})
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode > 399 {
		return nil, fmt.Errorf("failed to download url %s (%d)", url, res.StatusCode)
	}

	return filesystem.NewFileFromBytes(res.Body, path.Base(url))
}
