// Adyen PAN reveal flow with self-implemented RSAES-PKCS1-v1_5 encryption.
//
// Identical to reveal-forge.js, but step 3 replaces node-forge with ~40 lines
// of code: the RFC 8017 §7.2.1 padding plus textbook square-and-multiply
// modular exponentiation on native BigInt. Only the RSA *public-key*
// operation is needed, so no private-key material is ever handled.

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
//    exported out of the WebCrypto engine and padded by our own code.
//    The modulus and exponent are extracted from the SPKI key by
//    round-tripping it through WebCrypto's JWK export, avoiding an ASN.1
//    parser.
const base64ToBytes = (base64) =>
  Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
const base64UrlToBytes = (base64Url) =>
  base64ToBytes(base64Url.replace(/-/g, "+").replace(/_/g, "/"));
const bytesToBigInt = (bytes) => BigInt(`0x${bytesToHex(bytes)}`);

const modPow = (base, exponent, modulus) => {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
};

/** RSAES-PKCS1-v1_5 encryption per RFC 8017 §7.2.1. */
const rsaesPkcs1V15Encrypt = ({ n, e, byteLength }, message) => {
  // EM = 0x00 || 0x02 || PS || 0x00 || M, where PS is random nonzero bytes.
  const psLength = byteLength - message.length - 3;
  if (psLength < 8) throw new Error("Message too long.");
  const ps = new Uint8Array(psLength);
  for (let i = 0; i < psLength; i++) {
    do {
      crypto.getRandomValues(ps.subarray(i, i + 1));
    } while (ps[i] === 0);
  }
  const em = new Uint8Array(byteLength);
  em[1] = 0x02;
  em.set(ps, 2);
  em.set(message, psLength + 3);
  const c = modPow(bytesToBigInt(em), e, n);
  return hexToBytes(c.toString(16).padStart(byteLength * 2, "0"));
};

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
const modulusBytes = base64UrlToBytes(jwk.n);
const rsaPubKey = {
  n: bytesToBigInt(modulusBytes),
  e: bytesToBigInt(base64UrlToBytes(jwk.e)),
  byteLength: modulusBytes.length,
};
const rawSecretKey = new Uint8Array(
  await crypto.subtle.exportKey("raw", secretKey),
);
const wrappedKey = rsaesPkcs1V15Encrypt(rsaPubKey, rawSecretKey);

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
