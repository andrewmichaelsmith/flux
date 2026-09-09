# Billing / payment-method API

Most dictionaries hunt secrets or CMS installs. A smaller class posts a
card object to every spelling of "add a payment method" and reads the
status code — it is not looking for a file, it is testing which hosts
accept an **unauthenticated write to billing**. A 404 answers "not this
one" and the sender moves on, leaving a body hash. Accepting the write
answers "this one", which is the state that earns a second visit.

## Paths and response

| Aspect | Behaviour |
| --- | --- |
| Tier A (path alone) | `[/api][/vN][/<owner>]*/<billing leaf>[/<id>]`, optional trailing slash, case-insensitive |
| — owner | `account(s)`, `user(s)`, `profile`, `customer(s)`, `settings`, `billing`, `payment(s)`, `subscription(s)`, `me` |
| — billing leaf | `payment-method(s)`, `payment_source(s)`, `card(s)`, `credit-card(s)`, `change_payment`, `update-card`, `card-update`, `payment-update`, `billing-info`, `payment-info`, `payment-details`, `billing-details` (each with `-`/`_`/no separator) |
| Tier B (body required) | An owner segment with **no** billing leaf (`/api/v1/account`, `/api/v1/profile/payment`) — claimed only when the body carries a card object |
| Methods | `GET`/`HEAD` (list or fetch), `POST` (create). `PUT`/`PATCH`/`DELETE` branches exist but are unreachable — see below |
| Response | `201` on create, `200` otherwise, `application/json`, a payment-method object |
| Upstream cost | None. The response contains no canary, so it works without an issuing key |

A create returns the stored instrument and names its own follow-ups:

```json
{"id":"pm_<random>","object":"payment_method",
 "card":{"brand":"visa","last4":"4242","fingerprint":"<random>",…},
 "customer":"cus_<random>","livemode":true,
 "default_source":"pm_<random>",
 "links":{"self":"…","set_default":"…/default","payouts":"/api/v1/payouts"}}
```

Log fields on `result: payment-api-probe`:

| Field | Meaning |
| --- | --- |
| `paymentApiAction` | `list`, `get`, `create`, `update`, `delete` |
| `paymentApiMethod` | Method used |
| `paymentApiResourceId` | Instrument id from the path, when one was addressed |
| `paymentCardLast4` | Last four digits of the submitted card — **never more** |
| `paymentCardBrand` | Brand from the issuer prefix |
| `paymentCardLuhnValid` | Whether the number is card-shaped |
| `paymentCardTestRange` | Whether it is a publicly-documented processor test number |
| `paymentCardholderName` | Name field as submitted |
| `paymentBodyFields` | Sorted key names of the submitted object — the sender's schema, without its values |
| `paymentBodyPreview` | Head of the body, card numbers redacted to their last four |

## Why

The two booleans are the point. `paymentCardTestRange` true means the
sender is carrying a documented processor test number, which is what an
integration check or a catalogue sweep looks like. `paymentCardLuhnValid`
true with `paymentCardTestRange` false is a different event entirely — a
card-shaped number that nobody publishes — and it is worth being able to
tell those apart on one log line rather than by eye afterwards.

**A submitted card number is never written down.** Only the last four
digits reach the log or the response, and the body preview passes
through a redactor that rewrites any Luhn-valid run of digits to its
last four first. The case that makes this trap worth building — someone
posting a real card — is exactly the case where the honeypot must not
become the place that stored it. Numbers that are not card-shaped are
left intact, so order ids and timestamps survive the preview.

Nothing in the response is a credential, so there is no fixed literal
here and no issuing key is required: identifiers are per-request random
(`pm_`, `cus_`, `fingerprint`), and the only echoed value is the last
four of the caller's own card, which is what a real processor returns
and is what makes the acknowledgement read as genuine.

The generic spellings are gated on the body rather than the address. A
bare `/api/v1/account` is not this trap's to answer — claiming it would
shadow an ordinary account endpoint on every deployment — so it is
claimed only when the request actually carries a card. The
discriminator is the body, not the path.

`links` names the operations the acknowledgement invites. A client that
only replays a dictionary ignores them; one that parses the answer has a
concrete next step, and which of the two happens is the measurement this
trap is for.

**The `PUT`/`PATCH`/`DELETE` branches are unreachable today.** The
top-level handler allows only `GET`, `HEAD` and `POST`, and turns
everything else away with a 405 before any trap is consulted. The
branches are written and unit-tested anyway, so that widening the gate
stays a one-line decision rather than a second implementation — but a
`DELETE` to a path here currently logs `method-not-allowed`, not
`payment-api-probe`.
