import { TOTP } from "totp-generator";
import type { WebAuthnData } from "./server";
import base32Encode from "base32-encode";

export function generate2FACode(passkey: WebAuthnData) {
    const secret = base32Encode(passkey.credentialID, "RFC4648");
    return TOTP.generate(secret, { digits: 6, period: 60 });
}
