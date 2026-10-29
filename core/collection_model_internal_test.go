package core

import (
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"
)

func TestCollectionMarshalJSONRedactsAllSecrets(t *testing.T) {
	t.Parallel()

	collection := NewAuthCollection("test")

	fields := []sentinelField{}
	fillSentinels(reflect.ValueOf(&collection.collectionAuthOptions).Elem(), "options", &fields)

	raw, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}

	// 5 token secrets + OAuth2 provider client secret + signing private key
	assertSecretsRedacted(t, "auth collection", fields, raw, 7)

	// sanity check that the non-secret fields are serialized
	if !strings.Contains(string(raw), "SENTINEL_") {
		t.Fatal("Expected the non-secret sentinels to be serialized")
	}
}
