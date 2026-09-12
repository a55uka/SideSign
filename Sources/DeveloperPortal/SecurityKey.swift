//
//  SecurityKey.swift
//  SideSign
//
//  Created by a55uka on 12/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//
//  Hardware security key (FIDO2/WebAuthn) second-factor support for Apple IDs.
//
//  Some Apple IDs are configured to require a hardware security key (a FIDO
//  certified key such as a YubiKey) instead of — or in addition to — the usual
//  trusted-device / SMS second factors. For those accounts the GrandSlam SRP
//  login (`authenticate`) completes its cryptographic proof successfully but
//  reports a second-factor `au` status that is *not* one of the phone/trusted
//  device types. The session is only usable once the user signs with their key.
//
//  The full ceremony, as performed by Apple's own clients (idmsa web widget,
//  macOS/iOS system sign-in) and by this package:
//
//   1. `POST GrandSlam/GsService2` (SRP "init" / "complete") succeeds and the
//      decrypted `spd` payload yields `adsid` + `GsIdmsToken`, but the response's
//      `Status.au` names a second-factor step instead of completing the login.
//
//   2. `GET https://gsa.apple.com/auth` — the GrandSlam secondary-auth surface —
//      sent with anisette headers and `X-Apple-Identity-Token:
//      base64("<adsid>:<GsIdmsToken>")`. The JSON response contains an
//      `fsaChallenge` object (searched for recursively, like Apple's own web
//      client does):
//
//          "fsaChallenge": {
//              "challenge":  "<opaque, single-use challenge string>",
//              "rpId":       "apple.com",
//              "keyHandles": [ "<base64 credential id>", ... ]
//          }
//
//      `keyNames` (human-readable key labels for UI, e.g. "YubiKey 5C NFC") may
//      appear anywhere in the document.
//
//   3. The *caller* performs the WebAuthn `get` assertion with those key handles
//      against the security key (on iOS via `ASAuthorizationSecurityKey...`, on
//      macOS via CTAP2, etc.) and hands the result back through the
//      `SecurityKeyHandler` closure. The signed-over clientDataJSON is whatever
//      the platform authenticator produced — Apple's servers accept the native
//      clientDataJSON verbatim (they are lenient about its `origin` fields; only
//      the embedded challenge and the signature matter).
//
//   4. `POST https://gsa.apple.com/auth/verify/security/key` with the same
//      anisette + identity-token headers and a JSON body of exactly these seven
//      camelCase fields (the capitalisation is load-bearing — note `credentialID`):
//
//          challenge         — the fsaChallenge string, passed through verbatim
//          clientData        — base64(clientDataJSON, exactly as signed)
//          signatureData     — base64(assertion signature)
//          authenticatorData — base64(raw authenticator data)
//          userHandle        — base64url-nopad(user handle), omitted if absent
//          credentialID      — base64url-nopad(asserted credential id)
//          rpId              — the relying party id ("apple.com")
//
//      Any 2xx status means the key was accepted.
//
//   5. `authenticate` is re-run: the SRP handshake now completes without a
//      pending second factor and proceeds to the app-token exchange as usual.
//

import Foundation

// MARK: - Public Data Types

/// A WebAuthn assertion challenge issued by Apple's GrandSlam secondary-auth
/// service for an Apple ID that is protected with a hardware security key.
///
/// This is parsed from the `fsaChallenge` object of the
/// `GET https://gsa.apple.com/auth` response (see the file header for the
/// complete ceremony).
public struct SecurityKeyChallenge: Sendable, Equatable {
    /// The opaque, single-use challenge string exactly as Apple issued it.
    ///
    /// Pass this through **verbatim** — it is echoed back unchanged in the
    /// verification body, and the authenticator signs a hash of its
    /// re-encoded form inside `clientDataJSON`.
    public let challenge: String

    /// Credential identifiers of the security keys enrolled with the Apple ID,
    /// decoded from the challenge's `keyHandles` (or `allowedCredentials`)
    /// entries. Only keys matching one of these identifiers may sign.
    public let allowedCredentials: [Data]

    /// The WebAuthn relying party identifier the key must assert for.
    /// Apple uses the bare domain `apple.com`.
    public let relyingPartyIdentifier: String

    /// Human-readable labels of the enrolled keys (e.g. "YubiKey 5C NFC"),
    /// suitable for display in the sign-in UI. May be empty if Apple did not
    /// include them.
    public let keyNames: [String]

    public init(challenge: String,
                allowedCredentials: [Data],
                relyingPartyIdentifier: String,
                keyNames: [String] = []) {
        self.challenge = challenge
        self.allowedCredentials = allowedCredentials
        self.relyingPartyIdentifier = relyingPartyIdentifier
        self.keyNames = keyNames
    }
}

/// A completed WebAuthn assertion for a `SecurityKeyChallenge`, produced by the
/// caller's security-key UI layer and submitted to Apple for verification.
///
/// Every field maps one-to-one onto the corresponding WebAuthn
/// `PublicKeyCredential` response members; nothing here is transformed by
/// SideSign apart from base64 re-encoding into the verification body.
public struct SecurityKeyAssertion: Sendable {
    /// The identifier of the credential that produced the signature
    /// (WebAuthn `credential.rawId`).
    public let credentialID: Data

    /// The serialized `clientDataJSON` **exactly as the authenticator signed
    /// it**. Never rebuild or re-serialize this — the signature covers these
    /// precise bytes.
    public let clientDataJSON: Data

    /// The raw authenticator data blob (WebAuthn `authenticatorData`):
    /// relying-party-id hash, flags, signature counter, and extensions.
    public let authenticatorData: Data

    /// The assertion signature over `authenticatorData || SHA-256(clientDataJSON)`,
    /// made by the credential's private key.
    public let signature: Data

    /// The user handle returned by the authenticator (WebAuthn `userHandle`),
    /// when the authenticator provides one.
    public let userHandle: Data?

    public init(credentialID: Data,
                clientDataJSON: Data,
                authenticatorData: Data,
                signature: Data,
                userHandle: Data? = nil) {
        self.credentialID = credentialID
        self.clientDataJSON = clientDataJSON
        self.authenticatorData = authenticatorData
        self.signature = signature
        self.userHandle = userHandle
    }
}

/// The JSON body Apple's `POST /auth/verify/security/key` endpoint expects.
///
/// The field names are load-bearing: they mirror what Apple's own web client
/// sends to the idmsa equivalent of this endpoint, including the unusual
/// capital `ID` in `credentialID`. Do not "fix" the casing.
struct SecurityKeyVerifyBody: Encodable {
    /// The fsaChallenge string, passed through verbatim.
    let challenge: String
    /// Standard base64 of the signed `clientDataJSON`.
    let clientData: String
    /// Standard base64 of the assertion signature.
    let signatureData: String
    /// Standard base64 of the raw authenticator data.
    let authenticatorData: String
    /// Base64url (unpadded) user handle; omitted when the authenticator
    /// did not return one.
    let userHandle: String?
    /// Base64url (unpadded) asserted credential id.
    let credentialID: String
    /// The relying party id, e.g. `"apple.com"`.
    let rpId: String

    /// Builds the verification body from an assertion result.
    ///
    /// Encoding notes: WebAuthn binary fields that Apple matches against
    /// identifiers use base64url without padding (`userHandle`, `credentialID`);
    /// opaque blobs use standard base64 (`clientData`, `signatureData`,
    /// `authenticatorData`); the challenge is passed through as-is.
    init(assertion: SecurityKeyAssertion, challenge: SecurityKeyChallenge) {
        self.init(
            challenge: challenge.challenge,
            clientData: assertion.clientDataJSON.base64EncodedString(),
            signatureData: assertion.signature.base64EncodedString(),
            authenticatorData: assertion.authenticatorData.base64EncodedString(),
            userHandle: assertion.userHandle?.base64URLEncodedNoPadding(),
            credentialID: assertion.credentialID.base64URLEncodedNoPadding(),
            rpId: challenge.relyingPartyIdentifier
        )
    }
}

public extension DeveloperPortal {
    /// Performs the user-facing half of the security-key ceremony.
    ///
    /// Called by `authenticate` once Apple signals that a hardware security key
    /// is required and the `fsaChallenge` has been fetched. Implementations
    /// should present the key names from the challenge, drive the platform
    /// authenticator (on iOS: `ASAuthorizationSecurityKeyPublicKeyCredentialProvider`
    /// via an `ASAuthorizationController`, which handles NFC tap and PIN entry),
    /// and return the resulting assertion.
    ///
    /// Throw `DeveloperPortalError.userCancelled` (or any error) to abort the
    /// sign-in.
    typealias SecurityKeyHandler = @Sendable (SecurityKeyChallenge) async throws -> SecurityKeyAssertion
}

// MARK: - Security-Key Ceremony

internal extension DeveloperPortal {

    /// Fetches a security-key assertion challenge from GrandSlam's
    /// secondary-auth surface.
    ///
    /// - Returns: The parsed challenge, or `nil` if Apple's response carried no
    ///   `fsaChallenge` — i.e. the pending second factor is *not* a hardware key.
    /// - Throws: Transport and HTTP errors; a `nil` return is only produced for
    ///   a well-formed response that simply has no security-key challenge.
    func fetchSecurityKeyChallenge(context: TwoFactorAuthContext) async throws -> SecurityKeyChallenge? {
        debugLog("[SideSign] Requesting security key challenge from GrandSlam secondary-auth surface...")
        verboseLog("[SideSign] fetchSecurityKeyChallenge for dsid: \(context.dsid)")

        var request = makeTwoFactorAuthRequest(url: Constants.URLs.grandSlamAuthChallenge, context: context)
        request.httpMethod = "GET"
        // The challenge response is plain JSON (unlike the plist-flavoured
        // phone/trusted-device endpoints this header set is shared with).
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] fetchSecurityKeyChallenge HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }

        let (data, response) = try await session.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.safeStatusCode ?? 0

        try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "fetchSecurityKeyChallenge")

        guard statusCode == HTTPStatusCodes.ok else {
            let rawStr = prettyJSONString(from: data)
            debugLog("[SideSign] fetchSecurityKeyChallenge failed (HTTP \(statusCode)): \(rawStr)")
            throw ServerError.badServerResponse(reason: "Security key challenge request failed (HTTP \(statusCode))", jsonPayload: rawStr)
        }

        guard let payload = parsePlistOrJSON(data) else {
            let rawStr = prettyJSONString(from: data)
            debugLog("[SideSign] fetchSecurityKeyChallenge returned an unparseable response: \(rawStr)")
            throw ServerError.invalidResponseFormat(rawPayload: rawStr)
        }

        guard let challenge = SecurityKeyChallengeParser.parse(from: payload) else {
            // A well-formed response without an fsaChallenge simply means the
            // pending second factor is not a hardware key.
            debugLog("[SideSign] GrandSlam response carries no security key challenge (fsaChallenge).")
            return nil
        }

        debugLog("[SideSign] Received security key challenge (rpId: \(challenge.relyingPartyIdentifier), keys: \(challenge.keyNames.joined(separator: ", ")), credentials: \(challenge.allowedCredentials.count))")
        verboseLog("[SideSign] Security key challenge: \(challenge.challenge)")
        return challenge
    }

    /// Runs the user-facing half of the ceremony and submits the resulting
    /// assertion to Apple.
    ///
    /// On success the GrandSlam session is verified and the caller (usually
    /// `authenticate`) should run the SRP login again to exchange it for tokens.
    func performSecurityKeyVerification(_ challenge: SecurityKeyChallenge,
                                        context: TwoFactorAuthContext,
                                        securityKeyHandler: SecurityKeyHandler?) async throws {
        guard let securityKeyHandler else {
            debugLog("[SideSign] Security key required but no securityKeyHandler was provided")
            throw DeveloperPortalError.requiresSecurityKeyAuthentication
        }

        debugLog("[SideSign] Requesting security key assertion from caller...")
        let assertion = try await securityKeyHandler(challenge)
        debugLog("[SideSign] Received security key assertion (credential: \(assertion.credentialID.base64URLEncodedNoPadding()))")

        try await submitSecurityKeyAssertion(assertion, for: challenge, context: context)
    }

    /// Submits a signed assertion to `POST /auth/verify/security/key` and
    /// validates Apple's response.
    ///
    /// Any 2xx status is success. Failures surface the error message Apple
    /// provides (GrandSlam error code / message pair) when one is present.
    func submitSecurityKeyAssertion(_ assertion: SecurityKeyAssertion,
                                    for challenge: SecurityKeyChallenge,
                                    context: TwoFactorAuthContext) async throws {
        debugLog("[SideSign] Submitting security key assertion to Apple for verification...")
        verboseLog("[SideSign] submitSecurityKeyAssertion for dsid: \(context.dsid), rpId: \(challenge.relyingPartyIdentifier)")

        let bodyData = try JSONEncoder().encode(SecurityKeyVerifyBody(assertion: assertion, challenge: challenge))

        var request = makeTwoFactorAuthRequest(url: Constants.URLs.securityKeyVerify, context: context)
        request.httpMethod = "POST"
        request.httpBody = bodyData
        // This endpoint speaks JSON, not the plist dialect used by the
        // phone/trusted-device verify endpoints.
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        if let allHeaders = request.allHTTPHeaderFields {
            verboseLog("[SideSign] submitSecurityKeyAssertion HTTP headers: \(prettyJSONString(from: sanitizeHeadersForLogging(allHeaders)))")
        }
        verboseLog("[SideSign] submitSecurityKeyAssertion body: \(prettyJSONString(from: bodyData))")

        let (data, response) = try await session.data(for: request)
        let httpResponse = response as? HTTPURLResponse
        let statusCode = httpResponse?.safeStatusCode ?? 0

        let rawStr = prettyJSONString(from: data)
        verboseLog("[SideSign] submitSecurityKeyAssertion raw response (HTTP \(statusCode)): \(rawStr)")

        try throwIfXMLUIErrorAlert(in: data, statusCode: statusCode, actionName: "submitSecurityKeyAssertion")

        guard (HTTPStatusCodes.ok...299).contains(statusCode) else {
            let responseDictionary = parsePlistOrJSON(data)
            let statusDictionary = responseDictionary?["Status"] as? [String: any Sendable]
            let message = (responseDictionary?["em"] as? String)
                       ?? (statusDictionary?["em"] as? String)
                       ?? HTTPStatusCodes.localizedDescription(for: statusCode)
            debugLog("[SideSign] Security key verification failed (HTTP \(statusCode)): \(message)")
            throw DeveloperPortalError.securityKeyVerificationFailed(cause: message)
        }

        debugLog("[SideSign] Security key verified successfully! Second factor satisfied.")
    }
}

// MARK: - Challenge Parsing

/// Parses the `fsaChallenge` WebAuthn challenge out of a GrandSlam
/// secondary-auth response payload.
///
/// Apple's web client locates the challenge the same way: it never assumes a
/// fixed document shape, it simply searches the payload (JSON, or the
/// `boot_args` blob of an HTML response) for the well-known keys. Matching that
/// behaviour here keeps the parser resilient to harmless layout changes.
public enum SecurityKeyChallengeParser {

    /// Extracts the challenge from a decoded response payload.
    ///
    /// - Returns: `nil` when the payload carries no `fsaChallenge` (the pending
    ///   second factor is not a hardware key) or when the challenge object is
    ///   missing the pieces a WebAuthn assertion requires.
    static func parse(from payload: [String: any Sendable]) -> SecurityKeyChallenge? {
        guard let challengeObject = findValues(named: "fsaChallenge", in: payload)
            .compactMap({ $0 as? [String: any Sendable] })
            .first,
            let challengeString = challengeObject["challenge"] as? String,
            !challengeString.isEmpty
        else {
            return nil
        }

        // Apple asserts against the bare domain when no rpId is supplied.
        let relyingPartyIdentifier = (challengeObject["rpId"] as? String)
            ?? (challengeObject["rp"] as? String)
            ?? Constants.GrandSlam.defaultSecurityKeyReliantPartyID

        // Enrolled keys usually arrive as "keyHandles" inside the challenge
        // object; the idmsa web flavour of the flow instead lists
        // "allowedCredentials" (an array, or a comma-joined string) elsewhere in
        // the document. Accept both spellings from both places.
        var keyHandleStrings: [String] = (challengeObject["keyHandles"] as? [String]) ?? []
        if keyHandleStrings.isEmpty, let inChallenge = challengeObject["allowedCredentials"] as? [String] {
            keyHandleStrings = inChallenge
        }
        if keyHandleStrings.isEmpty {
            for candidate in findValues(named: "allowedCredentials", in: payload) {
                if let list = candidate as? [String] {
                    keyHandleStrings += list
                } else if let joined = candidate as? String {
                    keyHandleStrings += joined.split(separator: ",").map(String.init)
                }
            }
        }

        let allowedCredentials = keyHandleStrings.compactMap { decodeFlexibleBase64($0) }
        guard !allowedCredentials.isEmpty else {
            return nil
        }

        // Key labels ("keyNames") can sit anywhere in the document; collect them
        // for the caller's UI.
        let keyNames = findValues(named: "keyNames", in: payload)
            .compactMap { $0 as? [String] }
            .flatMap { $0 }

        return SecurityKeyChallenge(
            challenge: challengeString,
            allowedCredentials: allowedCredentials,
            relyingPartyIdentifier: relyingPartyIdentifier,
            keyNames: keyNames
        )
    }

    /// Depth-first search collecting every value stored under `key` anywhere in
    /// a JSON/plist-shaped tree of dictionaries and arrays.
    static func findValues(named key: String, in node: Any) -> [Any] {
        var results: [Any] = []
        if let dictionary = node as? [String: any Sendable] {
            for (childKey, value) in dictionary {
                if childKey == key {
                    results.append(value)
                }
                results.append(contentsOf: findValues(named: key, in: value))
            }
        } else if let array = node as? [any Sendable] {
            for value in array {
                results.append(contentsOf: findValues(named: key, in: value))
            }
        }
        return results
    }

    /// Decodes the base64 flavours Apple uses interchangeably in these payloads:
    /// standard and URL-safe alphabets, with or without padding.
    ///
    /// Callers performing the assertion themselves need this to turn
    /// `SecurityKeyChallenge.challenge` into the raw bytes the authenticator
    /// signs over (e.g. for `createCredentialAssertionRequest(challenge:)`).
    ///
    /// Returns `nil` for empty or malformed input — an empty challenge or key
    /// handle is never meaningful.
    public static func decodeFlexibleBase64(_ string: String) -> Data? {
        let sanitized = string
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard !sanitized.isEmpty else { return nil }
        let padded = sanitized + String(repeating: "=", count: (4 - sanitized.count % 4) % 4)
        return Data(base64Encoded: padded)
    }
}

// MARK: - Encoding Helpers

internal extension Data {
    /// Standard base64 re-encoded with the URL-safe alphabet and no `=`
    /// padding — the encoding Apple expects for WebAuthn identifier fields
    /// (`userHandle`, `credentialID`) in the security-key verification body.
    func base64URLEncodedNoPadding() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
