# Inbound webhook receiver

Tooling that posts its results to a collector sometimes posts them here
instead — same request, wrong host. Those arrive as deliveries to a
webhook-shaped path with a token in it. A 404 ends the exchange with
only a body hash to show for it; an acknowledgement keeps the payload.

## Paths and response

| Aspect | Behaviour |
| --- | --- |
| Paths | `/api/[vN/]webhook[s]/<token>/<verb>`, verb one of `event`, `events`, `callback`, `delivery`, `deliveries`, optional trailing slash, case-insensitive |
| Token | 4–128 of `A-Za-z0-9._:-` |
| Methods | `GET`, `HEAD`, `POST` |
| Response | `200`, `application/json`, `{"ok":true,"deliveryId":"<uuid4>","receivedAt":"<iso8601>"}` |
| Upstream cost | None. The acknowledgement contains no canary, so it works without an issuing key |

Deliberately **not** claimed, because each is a different surface with a
different answer: `/api/v1/webhook/<token>` (the subscription itself),
`/api/v1/webhooks` (the management collection), and anything with a
further path segment after the verb.

Log fields on `result: webhook-delivery`:

| Field | Meaning |
| --- | --- |
| `webhookToken` | The sender's own identifier for wherever it thought it was posting |
| `webhookMethod` | Method used |
| `webhookContentType` | Declared content type |
| `webhookBodyPreview` | Head of the body, bounded by `HONEYPOT_WEBHOOK_RECEIVER_BODY_PREVIEW_LIMIT` |

## Why

A delivery endpoint that 404s gets one attempt and a body hash. One that
acknowledges gets the payload — and, because senders retry and batch
against an endpoint that works, usually more than one. The body is the
whole point: it is the sender's own account of what it thinks it
collected.

The token is worth logging separately because it is chosen by the
sender, not by us. When it happens to be credential-shaped, the
[canary-echo observer](./canary-echo.md) has already classified it on
the same line, so one row says both that a delivery arrived and whose
key it was addressed to.

Matching is on path shape alone. Nothing about the token changes the
response — a client cannot learn anything about a credential by putting
it in the address.

The acknowledgement carries no credential-shaped field at all. A
receiver has no reason to hand its sender a secret, so there is nothing
here that could become a fixed literal shipped identically by every
deployment. `deliveryId` is a per-request uuid4, which is what a real
receiver echoes back.
