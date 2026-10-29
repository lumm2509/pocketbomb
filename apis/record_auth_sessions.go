package apis

import (
	"net/http"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/tools/types"
)

// accountSessionResponse is the public representation of an own auth session
// (an explicit allow-list: no hashes, secrets or flow request parameters).
type accountSessionResponse struct {
	Id string `json:"id"`

	// SSO indicates a root SSO (browser) session; the others are client sessions.
	SSO bool `json:"sso"`

	// Parent is the root SSO session of a client session (if any).
	Parent string `json:"parent"`

	// ClientId and ClientName of the OAuth2 client (empty for the root SSO sessions).
	ClientId   string `json:"clientId"`
	ClientName string `json:"clientName"`

	// Current indicates the session of the request access token and its root SSO session
	// (ending the current root SSO session logs out every non-offline session of that browser).
	Current bool `json:"current"`

	IP          string                   `json:"ip"`
	UserAgent   string                   `json:"userAgent"`
	AuthMethods []core.AuthSessionMethod `json:"authMethods"`
	Created     types.DateTime           `json:"created"`
	LastUsedAt  types.DateTime           `json:"lastUsedAt"`
	ExpiresAt   types.DateTime           `json:"expiresAt"`
}

// isOwnAccountSession reports whether the session is an own (not impersonated)
// session of the provided auth record.
//
// note: the impersonation sessions are activities of the impersonator (staff)
// and they are managed only by the staff (see [authSessionEnd]).
func isOwnAccountSession(session *core.AuthSession, authRecord *core.Record) bool {
	return session.CollectionRef() == authRecord.Collection().Id &&
		session.RecordRef() == authRecord.Id &&
		session.Impersonator() == ""
}

// GET /api/collections/{collection}/sessions
//
// Returns the active own auth sessions (root SSO and client sessions)
// of the authenticated record (first-party tokens only, like the other
// account actions and the remembered consents).
func recordAuthSessionsList(e *core.RequestEvent) error {
	authRecord := e.Auth

	sessions, err := e.App.FindAllAuthSessionsByRecord(authRecord)
	if err != nil {
		return e.InternalServerError("Failed to load the auth sessions.", err)
	}

	var currentId, currentRoot string
	if data, _ := e.Get(core.RequestEventKeyOAuth2).(*core.RequestInfoOAuth2); data != nil {
		currentId = data.SessionId
	}

	active := make([]*core.AuthSession, 0, len(sessions))
	for _, s := range sessions {
		if s.IsActive() && isOwnAccountSession(s, authRecord) {
			active = append(active, s)
			if s.Id == currentId {
				currentRoot = s.Parent()
			}
		}
	}

	clients := map[string]*core.OAuth2Client{}

	result := make([]*accountSessionResponse, 0, len(active))
	for _, s := range active {
		item := &accountSessionResponse{
			Id:          s.Id,
			SSO:         s.IsRoot(),
			Parent:      s.Parent(),
			Current:     currentId != "" && (s.Id == currentId || (currentRoot != "" && s.Id == currentRoot)),
			IP:          s.IP(),
			UserAgent:   s.UserAgent(),
			AuthMethods: s.AuthMethods(),
			Created:     s.Created(),
			LastUsedAt:  s.LastUsedAt(),
			ExpiresAt:   s.ExpiresAt(),
		}

		if clientRef := s.Client(); clientRef != "" {
			client, ok := clients[clientRef]
			if !ok {
				client, _ = e.App.FindOAuth2ClientById(clientRef)
				clients[clientRef] = client
			}
			if client != nil {
				item.ClientId = client.ClientId()
				item.ClientName = client.Name()
			}
		}

		result = append(result, item)
	}

	return e.JSON(http.StatusOK, result)
}

// POST /api/collections/{collection}/sessions/{id}/end
//
// Ends an own auth session of the authenticated record (with the regular cascade:
// ending a root SSO session ends its non-offline children, aka. a logout of that browser).
//
// A session of another record (or a missing one) is reported as not found.
func recordAuthSessionEnd(e *core.RequestEvent) error {
	session, err := e.App.FindAuthSessionById(e.Request.PathValue("id"))
	if err != nil || !isOwnAccountSession(session, e.Auth) {
		return e.NotFoundError("", err)
	}

	if err := e.App.EndAuthSession(session, "Account session end request"); err != nil {
		return e.BadRequestError("Failed to end the auth session.", err)
	}

	return e.NoContent(http.StatusNoContent)
}
