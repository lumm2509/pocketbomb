package core

import (
	"slices"
	"strings"
)

// systemSecretFields is the registry of the system collections secret fields
// (in addition to the password and tokenKey fields of every collection).
//
// The fields listed in systemInternalFields are a subset that is never
// exposed by the API, not even to the Owners.
var systemSecretFields = map[string][]string{
	CollectionNameOAuth2Clients:            {"clientSecretHash"},
	CollectionNameWebhooks:                 {"secret"},
	CollectionNameAPIKeys:                  {"tokenHash"},
	CollectionNameApplicationInstallations: {"webhookSecret"},
	CollectionNameAuthSessions: {
		"handleHash",
		"bindingHash",
		"codeHash",
		"refreshTokenHash",
		"prevRefreshTokenHash",
		"ssoSecretHash",
		"impersonatorKeyHash",
		"upstreamProvider",
		"upstreamRecordRef",
		"upstreamState",
		"upstreamCodeVerifier",
	},
}

var systemInternalFields = map[string][]string{
	CollectionNameOAuth2Clients: {"clientSecretHash"},
	CollectionNameWebhooks:      {"secret"},
	CollectionNameAPIKeys:       {"tokenHash"},
	CollectionNameAuthSessions: {
		"handleHash",
		"bindingHash",
		"codeHash",
		"refreshTokenHash",
		"prevRefreshTokenHash",
		"ssoSecretHash",
		"upstreamProvider",
		"upstreamRecordRef",
		"upstreamState",
		"upstreamCodeVerifier",
	},
}

// IsSecretField reports whether the provided collection field holds a secret
// (e.g. it could be used to forge tokens or to take over an account) and
// therefore could be exported, filtered or set only by the Owners:
//   - all password fields (incl. the OTPs)
//   - the auth collections tokenKey
//   - the registered system collections secret fields
//   - the "secret", "*Secret" and "*Hash" fields of the other system collections
func IsSecretField(collection *Collection, field Field) bool {
	if collection == nil || field == nil {
		return false
	}

	if field.Type() == FieldTypePassword {
		return true
	}

	name := field.GetName()

	if collection.IsAuth() && name == FieldNameTokenKey {
		return true
	}

	if !collection.System {
		return false
	}

	if fields, ok := systemSecretFields[collection.Name]; ok {
		return slices.Contains(fields, name)
	}

	return isSecretFieldName(name)
}

func isSecretFieldName(name string) bool {
	return name == "secret" || strings.HasSuffix(name, "Hash") || strings.HasSuffix(name, "Secret")
}

// SecretFieldNames returns the names of the provided collection secret fields (see [IsSecretField]).
func SecretFieldNames(collection *Collection) []string {
	result := []string{}

	for _, f := range collection.Fields {
		if IsSecretField(collection, f) {
			result = append(result, f.GetName())
		}
	}

	return result
}

// InternalFieldNames returns the names of the provided collection secret fields
// that are never exposed by the API (not even to the Owners).
func InternalFieldNames(collection *Collection) []string {
	if collection == nil || !collection.System {
		return nil
	}

	return systemInternalFields[collection.Name]
}
