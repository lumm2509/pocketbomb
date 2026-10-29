package core

import (
	validation "github.com/pocketbase/ozzo-validation/v4"
)

func checkOAuth2ServerDefaultCollection(app App) validation.RuleFunc {
	return func(value any) error {
		v, _ := value.(OAuth2ServerSettingsConfig)
		if v.DefaultCollection == "" {
			return nil // nothing to check
		}

		collection, err := app.FindCachedCollectionByNameOrId(v.DefaultCollection)
		if err != nil || !collection.IsAuth() {
			return validation.Errors{
				"defaultCollection": validation.NewError("validation_invalid_auth_collection", "Missing or invalid auth collection."),
			}
		}

		return nil
	}
}

type OAuth2ServerSettingsConfig struct {
	// DefaultCollection is the name or id of the auth collection whose
	// OAuth2 server (aka. OpenID Connect provider) issuer metadata is
	// served at the app root "/.well-known/*" endpoints.
	//
	// Leave empty to disable the root discovery endpoints.
	DefaultCollection string `form:"defaultCollection" json:"defaultCollection"`
}

// Validate makes OAuth2ServerSettingsConfig validatable by implementing [validation.Validatable] interface.
func (c OAuth2ServerSettingsConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.DefaultCollection, validation.Length(0, 255)),
	)
}
