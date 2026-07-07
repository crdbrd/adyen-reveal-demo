// Adyen PAN reveal flow, as it could look with only standard WebCrypto.
//
// This file is identical to reveal-forge.js except for step 3: the AES key
// is wrapped with crypto.subtle.wrapKey() and RSA-OAEP, the only RSA
// encryption padding WebCrypto supports. No third-party crypto library, and
// the AES key never leaves the browser's crypto engine in raw form.
//
// Today this fails at step 4, because the reveal endpoint only accepts
// RSAES-PKCS1-v1_5 padding. If the endpoint (optionally) accepted RSA-OAEP,
// this file would be the whole integration.

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

// 3. Wrap the AES key with Adyen's RSA public key, without the raw key ever
//    leaving the WebCrypto engine.
const base64ToBytes = (base64) =>
  Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
const rsaPubKey = await crypto.subtle.importKey(
  "spki",
  base64ToBytes(publicKey),
  { name: "RSA-OAEP", hash: "SHA-256" },
  false,
  ["wrapKey"],
);
const wrappedKey = new Uint8Array(
  await crypto.subtle.wrapKey("raw", secretKey, rsaPubKey, {
    name: "RSA-OAEP",
  }),
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
