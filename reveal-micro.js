// Adyen PAN reveal flow using micro-rsa-dsa-dh instead of node-forge.
//
// Identical to reveal-forge.js, but step 3 uses PKCS1_KEM from
// micro-rsa-dsa-dh (the noble-cryptography team's RSA library), a much
// smaller dependency than node-forge.

import { PKCS1_KEM } from "micro-rsa-dsa-dh/rsa.js";

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
//    exported out of the WebCrypto engine and handed to micro-rsa-dsa-dh.
//    The modulus and exponent are extracted from the SPKI key by
//    round-tripping it through WebCrypto's JWK export, avoiding an ASN.1
//    parser.
const base64ToBytes = (base64) =>
  Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
const base64UrlToBytes = (base64Url) =>
  base64ToBytes(base64Url.replace(/-/g, "+").replace(/_/g, "/"));
const bytesToBigInt = (bytes) => BigInt(`0x${bytesToHex(bytes)}`);
const jwk = await crypto.subtle.exportKey(
  "jwk",
  await crypto.subtle.importKey(
    "spki",
    base64ToBytes(publicKey),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["wrapKey"],
  ),
);
const rsaPubKey = {
  n: bytesToBigInt(base64UrlToBytes(jwk.n)),
  e: bytesToBigInt(base64UrlToBytes(jwk.e)),
};
const rawSecretKey = new Uint8Array(
  await crypto.subtle.exportKey("raw", secretKey),
);
const wrappedKey = PKCS1_KEM.encrypt(rsaPubKey, rawSecretKey);

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
