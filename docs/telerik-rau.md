# Telerik UI RadAsyncUpload handler

Answers the handler-registration check that a Telerik
`RadAsyncUpload` exploit makes before it fires, and captures the
upload that follows.

## Routes

| Method | Path | Query | Response | Result tag |
| --- | --- | --- | --- | --- |
| `GET` / `HEAD` | `/Telerik.Web.UI.WebResource.axd` | `type=rau` | `200` JSON registration notice | `telerik-rau-probe` |
| `POST` | `/Telerik.Web.UI.WebResource.axd` | `type=rau` | `200` JSON upload receipt | `telerik-rau-upload` |
| `POST` | `/Telerik.Web.UI.WebResource.axd` | `type=rau`, no descriptor and no file part | `200` JSON upload receipt | `telerik-rau-noupload` |
| any | `/Telerik.Web.UI.WebResource.axd` | anything but `type=rau` | `404`, empty body | `telerik-webresource-miss` |

The path is matched at the webroot only and case-insensitively, since
IIS resolves paths case-insensitively and the handler registers at the
application root. Prefixed spellings are deliberately not matched: an
unbounded prefix walk on a `.axd` suffix would take traffic belonging to
the other ASP.NET traps, and the observed probes spell it bare.

## What the handler parses

On `POST` it pulls the `rauPostData` descriptor out of the body — by
scanning for the field name rather than parsing a format, so both the
urlencoded and multipart spellings resolve and a hand-rolled or
truncated body still yields the value. It records the descriptor
(length-capped), the multipart field names, filenames and content
types, which of the public gadget type-names appear in the body
(`telerikGadgetIndicators`), and which payload extensions the filenames
carry (`telerikPayloadExtensions`) — a `.dll` is the deserialization
chain, an `.aspx` is a plain webshell, and they are different operators
using one CVE.

Nothing is written anywhere. The receipt exists so the sender believes
the drop landed and goes on to request what it thinks it uploaded —
that follow-up request is the signal that the chain completed, and it
lands in the access log on its own.

## Why

The `type=rau` registration notice is a pure fingerprint: it carries no
secret, and a real build answers it identically on every host. It is
also the gate. A version-gated exploit asks for it first and only ships
the AES-encrypted descriptor plus the mixed-mode assembly if the notice
comes back, so a `404` here costs the one request that carries the
payload. That payload never appears in a path dictionary, which makes
the `POST` the only place the gadget chain is observable at all.

Three design points follow from that:

* **The notice is byte-exact, typo included.** The shipped product
  misspells "succesfully". Correcting it would be a tell, so this is the
  one response in the trap with no per-hit variation.
* **The opaque fields in the receipt are per-hit unique.** `metaData` is
  random bytes and `tempFileName` a fresh identifier on every hit. A
  fixed value would ship one identical string from every sensor and let
  a replay recognise the trap by it.
* **A path hit without `type=rau` stays a 404.** Bare
  `WebResource.axd` is ASP.NET's own static web-resource handler, which
  404s without a valid resource reference — so the 404 is correct
  upstream behaviour, not a renderer gap to be closed by a later sweep.
  It also keeps a sender replaying a path list separable from one doing
  the real fingerprint check.

The probe arrives as part of a broad-spectrum enterprise-product
fingerprint sweep — one pass that asks each product for the asset or
version file that identifies it, spread across several hosts so no
single address asks for the whole list. Answering one product's
fingerprint rather than every product's is deliberate: a host that
simultaneously claims to be every enterprise application in the
dictionary is its own fingerprint.
