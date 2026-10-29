package apis

import (
	"errors"
	"net/http"
	"time"

	"github.com/lumm2509/pocketbomb/core"
	"github.com/lumm2509/pocketbomb/mails"
	"github.com/lumm2509/pocketbomb/tools/routine"
)

// recordRequestVerification sends a verification email to the authenticated actor
// (the actor confirms it with the issuer hosted verify-email page).
func recordRequestVerification(e *core.RequestEvent) error {
	collection, err := findAuthCollection(e)
	if err != nil {
		return err
	}

	if collection.Name == core.CollectionNameSuperusers {
		return e.BadRequestError("All superusers are verified by default.", nil)
	}

	record := e.Auth
	if record == nil || record.Collection().Id != collection.Id {
		return e.UnauthorizedError("The request requires valid record authorization token.", nil)
	}

	return requestRecordVerification(e, record, func() error {
		return e.NoContent(http.StatusNoContent)
	})
}

// requestRecordVerification triggers the OnRecordRequestVerificationRequest hook
// and sends a verification email to the provided record in the background
// (it is no-op if the record is already verified or an email was sent recently).
//
// It is shared by the authenticated actor API and the issuer hosted request page.
func requestRecordVerification(e *core.RequestEvent, record *core.Record, respond func() error) error {
	resendKey := getVerificationResendKey(record)
	if !record.Verified() && e.App.Store().Has(resendKey) {
		// eagerly write the response as a very basic measure against emails enumeration
		if err := respond(); err != nil {
			return err
		}
		return errors.New("try again later - you've already requested a verification email")
	}

	event := new(core.RecordRequestVerificationRequestEvent)
	event.RequestEvent = e
	event.Collection = record.Collection()
	event.Record = record

	return e.App.OnRecordRequestVerificationRequest().Trigger(event, func(e *core.RecordRequestVerificationRequestEvent) error {
		if e.Record.Verified() {
			return respond()
		}

		// run in background because we don't need to show the result to the client
		app := e.App
		record := e.Record
		routine.FireAndForget(func() {
			if err := mails.SendRecordVerification(app, record); err != nil {
				app.Logger().Error("Failed to send verification email", "error", err)
			}

			app.Store().Set(resendKey, struct{}{})
			time.AfterFunc(2*time.Minute, func() {
				app.Store().Remove(resendKey)
			})
		})

		return execAfterSuccessTx(true, e.App, respond)
	})
}

func getVerificationResendKey(record *core.Record) string {
	return "@limitVerificationEmail_" + record.Collection().Id + record.Id
}
