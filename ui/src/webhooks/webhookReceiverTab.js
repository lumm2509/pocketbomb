/**
 * Returns the webhook receiver docs (headers and verification snippets).
 *
 * @return {Element}
 */
export function webhookReceiverTab() {
    const headers = [
        [
            "X-PB-Hmac-Sha256",
            "Base64 HMAC-SHA256 signature of the raw request body (signed with the subscription secret).",
        ],
        [
            "X-PB-Event-Id",
            "Event identifier - the same across retries and redeliveries (use it for deduplication).",
        ],
        ["X-PB-Webhook-Id", "Delivery identifier (unique per delivery)."],
        ["X-PB-Topic", "The event topic, e.g. posts.create."],
        ["X-PB-Triggered-At", "When the event occurred (RFC3339)."],
        ["X-PB-Api-Version", "The payload API version."],
        ["X-PB-Test", "Set to \"true\" for test deliveries."],
    ];

    return t.div(
        { className: "webhook-receiver-tab" },
        t.p(
            { className: "txt-hint" },
            "Respond with any 2xx status within the configured timeout. Other responses (or timeouts) are retried with exponential backoff. The delivery is at-least-once, so dedupe by ",
            t.code(null, "X-PB-Event-Id"),
            ".",
        ),
        t.table(
            { className: "table webhook-headers-table" },
            t.tbody(
                null,
                headers.map(([h, d]) =>
                    t.tr(
                        null,
                        t.td({ className: "min-width" }, t.code(null, h)),
                        t.td({ className: "txt-hint" }, d),
                    )
                ),
            ),
        ),
        app.components.codeBlockTabs({
            className: "webhook-receiver-snippets",
            historyKey: "pbWebhookReceiverTab",
            tabs: () => [
                {
                    title: "Node.js (express)",
                    language: "js",
                    value: `
import crypto from "node:crypto";
import express from "express";

const app = express();
const secret = process.env.PB_WEBHOOK_SECRET;
const seen = new Set(); // use a persistent store in production

// note: the signature is calculated from the RAW body
app.post("/webhooks/pocketbase", express.raw({ type: "*/*" }), (req, res) => {
    const expected = crypto.createHmac("sha256", secret).update(req.body).digest();
    const provided = Buffer.from(req.get("X-PB-Hmac-Sha256") || "", "base64");

    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
        return res.sendStatus(401);
    }

    const eventId = req.get("X-PB-Event-Id");
    if (seen.has(eventId)) {
        return res.sendStatus(200); // already processed
    }
    seen.add(eventId);

    const topic = req.get("X-PB-Topic");
    const event = JSON.parse(req.body.toString("utf8"));
    console.log(topic, eventId, event.record?.id);

    res.sendStatus(200);
});

app.listen(3000);
`.trim(),
                },
                {
                    title: "Go",
                    language: "go",
                    value: `
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "io"
    "log"
    "net/http"
    "os"
    "sync"
)

func main() {
    secret := []byte(os.Getenv("PB_WEBHOOK_SECRET"))
    var seen sync.Map // use a persistent store in production

    http.HandleFunc("POST /webhooks/pocketbase", func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
        if err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }

        // (or use webhooks.Verify(r, secret) from "github.com/lumm2509/pocketbomb/tools/webhooks")
        mac := hmac.New(sha256.New, secret)
        mac.Write(body)
        provided, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-PB-Hmac-Sha256"))
        if !hmac.Equal(mac.Sum(nil), provided) {
            http.Error(w, "invalid signature", http.StatusUnauthorized)
            return
        }

        eventId := r.Header.Get("X-PB-Event-Id")
        if _, dup := seen.LoadOrStore(eventId, true); dup {
            w.WriteHeader(http.StatusOK) // already processed
            return
        }

        var event map[string]any
        _ = json.Unmarshal(body, &event)
        log.Println(r.Header.Get("X-PB-Topic"), eventId)

        w.WriteHeader(http.StatusOK)
    })

    log.Fatal(http.ListenAndServe(":3000", nil))
}
`.trim(),
                },
                {
                    title: "PHP",
                    language: "php",
                    value: `
<?php
$secret = getenv('PB_WEBHOOK_SECRET');
$body = file_get_contents('php://input'); // raw body

$expected = base64_encode(hash_hmac('sha256', $body, $secret, true));
$provided = $_SERVER['HTTP_X_PB_HMAC_SHA256'] ?? '';

if (!hash_equals($expected, $provided)) {
    http_response_code(401);
    exit;
}

$eventId = $_SERVER['HTTP_X_PB_EVENT_ID'] ?? '';
// dedupe by $eventId (e.g. unique db index) ...

$event = json_decode($body, true);
http_response_code(200);
`.trim(),
                },
                {
                    title: "Payload example",
                    language: "js",
                    value: `
// collection topics (e.g. posts.update)
{
    "action": "update",
    "collectionId": "pbc_1234567890",
    "collectionName": "posts",
    "record": { "id": "...", "title": "...", ... }, // honors the "Payload fields" option
    "changedFields": ["title"], // update only
    "authMethod": "password"    // auth only
}

// custom topics - the payload passed to app.Webhooks().Trigger(ctx, topic, payload)
`.trim(),
                },
            ],
        }),
    );
}
