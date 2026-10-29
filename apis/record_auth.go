package apis

import (
	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/router"
)

// bindRecordAuthApi registers the auth record actor api endpoints and
// the corresponding handlers.
//
// Note that the authentication itself (and the account flows like password reset
// and email verification/change confirmation) are handled by the OAuth2 server
// hosted pages (see bindOAuth2ServerApi).
func bindRecordAuthApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/collections/{collection}")

	sub.POST("/request-verification", recordRequestVerification).Bind(
		collectionPathRateLimit("", "requestVerification"),
		RequireSameCollectionContextAuth(""),
	)

	sub.POST("/request-email-change", recordRequestEmailChange).Bind(
		RequireFirstPartyToken(),
		collectionPathRateLimit("", "requestEmailChange"),
		RequireSameCollectionContextAuth(""),
	)

	// own auth sessions (the same account action guards as above)
	sub.GET("/sessions", recordAuthSessionsList).Bind(
		RequireFirstPartyToken(),
		RequireSameCollectionContextAuth(""),
	)
	sub.POST("/sessions/{id}/end", recordAuthSessionEnd).Bind(
		RequireFirstPartyToken(),
		collectionPathRateLimit("", "endSession"),
		RequireSameCollectionContextAuth(""),
	)
}

func findAuthCollection(e *core.RequestEvent) (*core.Collection, error) {
	collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue("collection"))

	if err != nil || !collection.IsAuth() {
		return nil, e.NotFoundError("Missing or invalid auth collection context.", err)
	}

	return collection, nil
}
