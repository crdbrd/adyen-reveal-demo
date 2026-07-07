// Adyen PAN reveal flow, as integrators must implement it today.
//
// Everything in this file uses the standard WebCrypto API, except step 3:
// wrapping the AES key with Adyen's RSA public key. The reveal endpoint
// requires RSAES-PKCS1-v1_5 padding, which WebCrypto does not support for
// encryption, so a userland crypto library (node-forge) must be shipped to
// the browser for this single operation.
//
// Compare with reveal-webcrypto.js, which is identical except for step 3.

import forge from "node-forge";

const API_BASE =
  process.env.ADYEN_API_BASE ??
  "https://balanceplatform-api-test.adyen.com/bcl/v2";

const apiKey = process.env.ADYEN_API_KEY;
const paymentInstrumentId = process.env.PAYMENT_INSTRUMENT_ID;
if (!apiKey || !paymentInstrumentId) {
  console.error(
    "Set the ADYEN_API_KEY and PAYMENT_INSTRUMENT_ID environment variables.",
  );
  process.exit(1);
}

const api = async (path, body) => {
  const response = await fetch(`${API_BASE}${path}`, {
    method: body ? "POST" : "GET",
    headers: { "x-api-key": apiKey, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(
      `${response.status} ${response.statusText}\n${JSON.stringify(json, null, 2)}`,
    );
  }
  return json;
};

const bytesToHex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex) =>
  Uint8Array.from(hex.match(/.{2}/g), (byte) => Number.parseInt(byte, 16));

// 1. Fetch Adyen's RSA public key.
const { publicKey } = await api("/publicKey?purpose=panReveal");

// 2. Generate a fresh AES-256 key. It must be extractable so that step 3
//    can wrap it.
const secretKey = await crypto.subtle.generateKey(
  { name: "AES-CBC", length: 256 },
  true,
  ["decrypt"],
);

// 3. Wrap the AES key with Adyen's RSA public key. The raw key must be
//    exported out of the WebCrypto engine and handed to node-forge.
//    THE ONE STEP WEBCRYPTO CANNOT DO: RSAES-PKCS1-v1_5 encryption.
const rsaPubKey = forge.pki.publicKeyFromPem(
  `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`,
);
const rawSecretKey = new Uint8Array(
  await crypto.subtle.exportKey("raw", secretKey),
);
const wrappedKey = Uint8Array.from(
  rsaPubKey.encrypt(String.fromCharCode(...rawSecretKey), "RSAES-PKCS1-V1_5"),
  (char) => char.charCodeAt(0),
);

// 4. Ask Adyen for the card details, encrypted with our AES key.
const { encryptedData } = await api("/paymentInstruments/reveal", {
  paymentInstrumentId,
  encryptedKey: bytesToHex(wrappedKey),
});

// 5. Decrypt the card details with our AES key. The protocol fixes the IV to
//    all zeros; that is tolerable only because the AES key is used for
//    exactly this one message.
const plaintext = await crypto.subtle.decrypt(
  { name: "AES-CBC", iv: new Uint8Array(16) },
  secretKey,
  hexToBytes(encryptedData),
);
console.log(JSON.parse(new TextDecoder().decode(plaintext)));
