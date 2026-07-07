# Adyen PAN reveal: userland RSA vs. standard WebCrypto

Stripped-down, self-contained implementations of the [Adyen Balance Platform
PAN reveal flow](https://docs.adyen.com/issuing/manage-card-data/reveal-card-details), run against the
Adyen test environment.

The flow requires wrapping an AES-256 session key with Adyen's RSA public key
using **RSAES-PKCS1-v1_5** padding. Browsers' built-in WebCrypto API
deliberately does not support that padding for encryption (only RSA-OAEP), so
this single step forces integrators to ship a userland RSA implementation.
Every other step of the flow is plain WebCrypto.

Apart from the opening comment and the library import, the variants are
identical except for step 3, the key wrapping — run
`diff reveal-webcrypto.js reveal-diy.js` to see the whole difference:

- **`reveal-webcrypto.js`** — only standard WebCrypto: the session key is
  wrapped with `crypto.subtle.wrapKey()` and RSA-OAEP. This is what the
  integration *could* look like; today it fails, because the reveal endpoint
  only accepts RSAES-PKCS1-v1_5.
- Three working userland RSAES-PKCS1-v1_5 implementations:
  - **`reveal-forge.js`** —
    [node-forge](https://github.com/digitalbazaar/forge)
  - **`reveal-micro.js`** — `PKCS1_KEM` from
    [micro-rsa-dsa-dh](https://github.com/paulmillr/micro-rsa-dsa-dh)
  - **`reveal-diy.js`** — self-implemented: RFC 8017 §7.2.1 padding plus
    BigInt modular exponentiation, ~40 lines, zero dependencies

## The ask

Let `POST /bcl/v2/paymentInstruments/reveal` (optionally) accept a session key
wrapped with **RSA-OAEP** instead of RSAES-PKCS1-v1_5. Then
`reveal-webcrypto.js` would be the complete client-side integration:

- **RSAES-PKCS1-v1_5 key transport is disallowed, not just discouraged.**
  [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
  disallows RSAES-PKCS1-v1_5 for key transport after 2023 — and wrapping the
  session key is key transport. The scheme's weakness is the Bleichenbacher
  family of padding-oracle attacks, which is why the ecosystem is actively
  removing it: WebCrypto omits it for encryption (keeping PKCS#1 v1.5 for
  *signatures* only), and Node.js disabled RSAES-PKCS1-v1_5 *decryption* by
  default in 2024
  ([CVE-2023-46809](https://nodejs.org/en/blog/vulnerability/february-2024-security-releases),
  the Marvin timing attack). RFC 8017 recommends OAEP for new applications
  and keeps RSAES-PKCS1-v1_5 only for compatibility with existing ones.
- **No userland crypto.** Whatever RSAES-PKCS1-v1_5 implementation an
  integrator picks, it is JavaScript crypto code that must be chosen,
  trusted, kept up to date, and shipped to every browser (see the size table
  below). With OAEP, the whole step is one call to the browser's built-in,
  audited crypto engine.
- **The session key never leaves the browser's crypto engine in raw form.**
  With `wrapKey()`, page JavaScript never touches the key bytes; today the
  key must be exported out of WebCrypto and handed to userland code.

## Cost of the userland RSA step

Complete flow bundled for the browser with esbuild (minified and gzipped;
reproduce with `npm run sizes`), 2026-07-07:

| Variant               | Minified | Gzipped |
| --------------------- | -------: | ------: |
| `reveal-forge.js`     |   288 kB |   77 kB |
| `reveal-micro.js`     |   5.9 kB |  2.6 kB |
| `reveal-diy.js`       |   1.8 kB |  1.0 kB |
| `reveal-webcrypto.js` |   1.2 kB |  0.7 kB |

Implementation notes:

- Only the RSA *public-key* operation is needed — pad the message per RFC
  8017 §7.2.1, then one modular exponentiation — so no private-key material
  is ever handled. With native `BigInt`, this fits in ~40 lines of
  dependency-free code (`reveal-diy.js`).
- `reveal-micro.js` and `reveal-diy.js` extract the modulus and exponent from
  Adyen's SPKI key by round-tripping it through WebCrypto's JWK export,
  avoiding an ASN.1 parser.
- None of the userland implementations are constant-time. The only secret on
  the encrypting side is the 32-byte session key inside the padded message,
  and the classic PKCS#1 v1.5 padding-oracle attacks (Bleichenbacher) target
  the *decryptor*, i.e. Adyen's side.
- The critical padding requirements (RFC 8017 §7.2.1): the padding string
  must be random *nonzero* bytes from a CSPRNG (`crypto.getRandomValues`),
  and at least 8 bytes long.
- The flow fixes the AES-CBC IV to all zeros. That is tolerable only because
  each session key encrypts exactly one message; it is not a bug in these
  demos.

## Running

Requires Node.js ≥ 20 (uses the same standard `fetch` and `crypto.subtle`
APIs that browsers provide; run under Node only because the Adyen API is not
CORS-enabled for direct browser access).

```sh
npm install
export ADYEN_API_KEY=...            # Balance Platform API key, test env
export PAYMENT_INSTRUMENT_ID=PI...  # An active card in the test env
node reveal-webcrypto.js
node reveal-forge.js
node reveal-micro.js
node reveal-diy.js
```

### Offline test (no credentials needed)

`npm test` runs every variant unmodified against a local mock of the two
Adyen endpoints: it serves a fresh RSA public key, unwraps the session key
with the private key, validates the RFC 8017 §7.2.1 padding, and answers
like the real reveal endpoint. Expected output mirrors the Adyen test
environment:

```
ok    reveal-forge.js reveals the card
ok    reveal-micro.js reveals the card
ok    reveal-diy.js reveals the card
ok    reveal-webcrypto.js is rejected (endpoint accepts no RSA-OAEP)
```

## Observed results (Adyen test environment, 2026-07-07)

The three RSAES-PKCS1-v1_5 variants succeed:

```
{
  pan: '5555444430644664',
  expiration: { month: '05', year: '2026' },
  cvc: '846'
}
```

`reveal-webcrypto.js` fails at the reveal call, since Adyen cannot unwrap the
OAEP-padded session key (same result with SHA-256 and SHA-1 OAEP parameters):

```
Error: 400 Bad Request
{
  "type": "https://docs.adyen.com/errors/bad-request",
  "title": "Bad request",
  "status": 400,
  "detail": "Invalid session key",
  "errorCode": "00_400"
}
```
