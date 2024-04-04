import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    type VerifiedRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { addNewAuthenticator, getPasskeyFromIDAndUser, getUserAuthenticators, getUserCurrentChallenge, setUserCurrentChallenge, updatePasskeyCounter, type User, type WebAuthnData } from './server';

// Human-readable title for your website
const rpName = process.env.WEBAUTHN_RPNAME ?? 'BorgHostAPI';
// A unique identifier for your website
const rpID = process.env.WEBAUTHN_RPID ?? 'borg-host-api';
// The URL at which registrations and authentications should occur
const origin = process.env.WEBAUTHN_ORIGIN ?? `https://${rpID}`;

export async function getRegistrationOptions(user: User) {
    // (Pseudocode) Retrieve any of the user's previously-
    // registered authenticators
    const userAuthenticators = getUserAuthenticators(user.uid);

    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.uid.toString(),
        userName: user.login,
        // Don't prompt users for additional information about the authenticator
        // (Recommended for smoother UX)
        attestationType: 'none',
        // Prevent users from re-registering existing authenticators
        excludeCredentials: userAuthenticators.map(authenticator => ({
            id: authenticator.credentialID as Uint8Array,
            type: 'public-key',
            // Optional
            transports: authenticator.transports,
        })),
        // See "Guiding use of authenticators via authenticatorSelection" below
        authenticatorSelection: {
            // Defaults
            residentKey: 'preferred',
            userVerification: 'preferred',
            // Optional
            authenticatorAttachment: 'platform',
        },
    });

    // (Pseudocode) Remember the challenge for this user
    setUserCurrentChallenge(user.uid, options.challenge)

    return options;
}

export async function verifyRegistrationRes(body: any, uid: number) {
    // (Pseudocode) Get `options.challenge` that was saved above
    const expectedChallenge: string = getUserCurrentChallenge(uid)!;

    let verification;
    try {
        verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
    } catch (error) {
        console.error(error);
        return { error: (error as any).message };
    }

    const { verified } = verification;

    if (verified) {
        const { registrationInfo } = verification as VerifiedRegistrationResponse;
        const {
            credentialPublicKey,
            credentialID,
            counter,
            credentialDeviceType,
            credentialBackedUp,
        } = registrationInfo!;

        const newAuthenticator: WebAuthnData = {
            name: body.name ?? "unnamed",
            credentialID,
            credentialPublicKey,
            counter,
            credentialDeviceType,
            credentialBackedUp,
            // `body` here is from Step 2
            transports: body.response.transports,
            uid,
        };
        
        addNewAuthenticator(newAuthenticator);
    }

    return { verified };
}

export async function getAuthenticationOptions(uid: number) {
    const userAuthenticators = getUserAuthenticators(uid);

    const options = await generateAuthenticationOptions({
        rpID,
        // Require users to use a previously-registered authenticator
        allowCredentials: userAuthenticators.map(authenticator => ({
            id: authenticator.credentialID,
            type: 'public-key',
            transports: authenticator.transports,
        })),
        userVerification: 'preferred',
    });

    // (Pseudocode) Remember this challenge for this user
    setUserCurrentChallenge(uid, options.challenge);

    return options;
}

export async function verifyAuthenticationRes(body: any, uid: number) {
    // (Pseudocode) Get `options.challenge` that was saved above
    const expectedChallenge = getUserCurrentChallenge(uid)!;
    // (Pseudocode} Retrieve an authenticator from the DB that
    // should match the `id` in the returned credential
    const authenticator = getPasskeyFromIDAndUser(uid, body.id);

    if (!authenticator) {
        throw new Error(`Could not find authenticator ${body.id} for user ${uid}`);
    }

    let verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator,
    });

    const { verified, authenticationInfo } = verification;

    updatePasskeyCounter(body.id, authenticationInfo.newCounter);

    return { verified };
}
