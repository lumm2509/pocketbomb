package apis

import (
	"github.com/lumm2509/pocketbomb/core"
)

// LoadAuthSession loads the hosted login flow auth session of the current
// /oauth2/{collection}/* request (from the "auth_state" query or form parameter)
// and checks its browser binding cookie.
//
// It could be used by custom auth method routes registered under the issuer path, e.g.:
//
//	se.Router.POST("/oauth2/{collection}/login/custom", func(e *core.RequestEvent) error {
//		session, err := apis.LoadAuthSession(e)
//		if err != nil {
//			return e.BadRequestError("Invalid sign-in request.", err)
//		}
//
//		// ... custom verification and record lookup ...
//
//		if err := apis.AddAuthSessionFactor(e, session, record, "custom", ""); err != nil {
//			return e.BadRequestError("Failed to authenticate.", err)
//		}
//
//		return apis.ContinueAuthSession(e, session)
//	})
func LoadAuthSession(e *core.RequestEvent) (*core.AuthSession, error) {
	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return nil, err
	}

	flow, err := loadOAuth2Flow(e, collection, oauth2FlowHandle(e))
	if err != nil {
		return nil, err
	}

	return flow.session, nil
}

// AddAuthSessionFactor registers a completed factor for the provided
// hosted login flow session (see [LoadAuthSession]).
//
// It triggers the [core.App.OnAuthSessionStepRequest] hook and on success
// identifies the session actor (if not already) and persists the factor.
func AddAuthSessionFactor(e *core.RequestEvent, session *core.AuthSession, record *core.Record, method string, provider string) error {
	flow, err := reloadOAuth2Flow(e, session)
	if err != nil {
		return err
	}

	if err := oauth2AddFactor(e, flow, record, method, provider); err != nil {
		return err
	}

	*session = *flow.session

	return nil
}

// ContinueAuthSession continues the hosted login flow of the provided session
// (see [LoadAuthSession]) by redirecting to the next required step
// (additional MFA factor, consent) or by issuing the authorization code.
func ContinueAuthSession(e *core.RequestEvent, session *core.AuthSession) error {
	flow, err := reloadOAuth2Flow(e, session)
	if err != nil {
		return err
	}

	return oauth2ContinueFlow(e, flow)
}

func reloadOAuth2Flow(e *core.RequestEvent, session *core.AuthSession) (*oauth2Flow, error) {
	if session == nil {
		return nil, errInvalidOAuth2Flow
	}

	collection, err := findOAuth2ServerCollection(e)
	if err != nil {
		return nil, err
	}

	flow, err := loadOAuth2Flow(e, collection, oauth2FlowHandle(e))
	if err != nil {
		return nil, err
	}

	if flow.session.Id != session.Id {
		return nil, errInvalidOAuth2Flow
	}

	return flow, nil
}
