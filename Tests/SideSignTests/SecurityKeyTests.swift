//
//  SecurityKeyTests.swift
//  SideSignTests
//
//  Created by a55uka on 12/09/26.
//  Copyright © 2026 SideSign. All rights reserved.
//
//  Unit tests for the hardware security key (FIDO2/WebAuthn) second-factor
//  support. These cover the pure data-mangling layers — challenge parsing and
//  verification-body encoding — whose exact byte/field behaviour is load-bearing
//  for interop with Apple's endpoints. The network and authenticator halves of
//  the ceremony require a real security key and are covered by on-device tests.
//

import Testing
import Foundation
@testable import SideSign

@Suite("Security Key Tests")
struct SecurityKeyTests {

    // MARK: - Base64 Helpers

    @Test
    func flexibleBase64DecodingHandlesStandardAndURLSafeAlphabets() throws {
        // Standard base64 with padding.
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64("aGVsbG8=") == Data("hello".utf8))
        // Standard base64 without padding.
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64("aGVsbG8") == Data("hello".utf8))
        // URL-safe alphabet: "-_" instead of "+/".
        let urlSafeBytes = Data([0xfb, 0xff, 0xbf, 0xfe, 0xaf, 0xff])
        let urlSafe = urlSafeBytes.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64(urlSafe) == urlSafeBytes)
        // Empty input is meaningless, never a valid key handle.
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64("   ") == nil)
    }

    @Test
    func flexibleBase64DecodingRejectsGarbage() {
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64("not base64!!") == nil)
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64("") == nil)
    }

    @Test
    func base64URLEncodingDropsPaddingAndUsesURLSafeAlphabet() {
        let bytes = Data([0xfb, 0xff, 0xbf, 0xfe, 0xaf, 0xff])
        let encoded = bytes.base64URLEncodedNoPadding()
        #expect(!encoded.contains("="))
        #expect(!encoded.contains("+"))
        #expect(!encoded.contains("/"))
        #expect(SecurityKeyChallengeParser.decodeFlexibleBase64(encoded) == bytes)
    }

    // MARK: - Challenge Parsing

    /// A realistic GrandSlam secondary-auth response: `fsaChallenge` at the top
    /// level with `keyHandles`, and key labels in a sibling collection.
    @Test
    func challengeParsingFromTypicalJSONResponse() throws {
        let payload = try DeveloperPortal.shared.parsePlistOrJSON(Data("""
        {
            "authType": "hardware-key",
            "fsaChallenge": {
                "challenge": "MTIzNDU2Nzg",
                "rpId": "apple.com",
                "keyHandles": ["AAECAwQFBgcICQ", "aGVsbG8"]
            },
            "keyNames": ["YubiKey 5C NFC", "Feitian ePass"]
        }
        """.utf8))

        let challenge = try #require(payload.flatMap { SecurityKeyChallengeParser.parse(from: $0) })

        #expect(challenge.challenge == "MTIzNDU2Nzg")
        #expect(challenge.relyingPartyIdentifier == "apple.com")
        #expect(challenge.allowedCredentials.count == 2)
        #expect(challenge.allowedCredentials[0] == Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
        #expect(challenge.allowedCredentials[1] == Data("hello".utf8))
        #expect(challenge.keyNames == ["YubiKey 5C NFC", "Feitian ePass"])
    }

    /// The idmsa web flavour of the flow: no `keyHandles` in the challenge
    /// object, but `allowedCredentials` (comma-joined string) elsewhere in the
    /// document; the parser must search for it recursively.
    @Test
    func challengeParsingSupportsAllowedCredentialsFallback() throws {
        let payload = try DeveloperPortal.shared.parsePlistOrJSON(Data("""
        {
            "userInfo": {
                "fsaChallenge": {
                    "challenge": "MTIzNDU2Nzg",
                    "rpId": "apple.com"
                },
                "allowedCredentials": "AAECAwQFBgcICQ,aGVsbG8"
            }
        }
        """.utf8))

        let challenge = try #require(payload.flatMap { SecurityKeyChallengeParser.parse(from: $0) })

        #expect(challenge.allowedCredentials.count == 2)
        #expect(challenge.allowedCredentials[1] == Data("hello".utf8))
    }

    /// When GrandSlam omits the `rpId` (or a challenge nests deeper than
    /// expected), the parser must still produce a usable challenge against the
    /// domain Apple actually asserts for.
    @Test
    func challengeParsingDefaultsRelyingPartyAndSearchesRecursively() throws {
        let payload = try DeveloperPortal.shared.parsePlistOrJSON(Data("""
        {
            "deeply": {
                "nested": {
                    "fsaChallenge": {
                        "challenge": "MTIzNDU2Nzg",
                        "keyHandles": ["AAECAwQFBgcICQ"]
                    }
                }
            }
        }
        """.utf8))

        let challenge = try #require(payload.flatMap { SecurityKeyChallengeParser.parse(from: $0) })

        #expect(challenge.relyingPartyIdentifier == Constants.GrandSlam.defaultSecurityKeyReliantPartyID)
        #expect(challenge.allowedCredentials.count == 1)
        #expect(challenge.keyNames.isEmpty)
    }

    /// A payload without an `fsaChallenge` means the pending second factor is
    /// *not* a hardware key — the parser must say so by returning nil, not by
    /// throwing or producing a partial challenge.
    @Test
    func challengeParsingReturnsNilWhenNoChallengePresent() throws {
        let payloads = try [
            DeveloperPortal.shared.parsePlistOrJSON(Data("{}".utf8)),
            DeveloperPortal.shared.parsePlistOrJSON(Data(#"{"fsaChallenge": {"rpId": "apple.com"}}"#.utf8)),
            DeveloperPortal.shared.parsePlistOrJSON(Data(#"{"fsaChallenge": {"challenge": "MTIzNDU2Nzg", "keyHandles": []}}"#.utf8)),
        ].compactMap { $0 }

        for payload in payloads {
            #expect(SecurityKeyChallengeParser.parse(from: payload) == nil)
        }
    }

    // MARK: - Verification Body

    /// Apple matches the verification body's field names exactly (including the
    /// capital `ID` in `credentialID`), so the encoded JSON must contain
    /// precisely these seven keys.
    @Test
    func verifyBodyEncodesExactAppleFieldNames() throws {
        let challenge = SecurityKeyChallenge(
            challenge: "MTIzNDU2Nzg",
            allowedCredentials: [Data("hello".utf8)],
            relyingPartyIdentifier: "apple.com",
            keyNames: []
        )
        let assertion = SecurityKeyAssertion(
            credentialID: Data("hello".utf8),
            clientDataJSON: Data(#"{"type":"webauthn.get"}"#.utf8),
            authenticatorData: Data([0x00, 0x01, 0x02]),
            signature: Data([0xde, 0xad]),
            userHandle: Data("user".utf8)
        )

        let bodyData = try JSONEncoder().encode(SecurityKeyVerifyBody(assertion: assertion, challenge: challenge))
        let json = try #require(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])

        let expectedKeys: Set<String> = [
            "challenge", "clientData", "signatureData", "authenticatorData",
            "userHandle", "credentialID", "rpId"
        ]
        #expect(Set(json.keys) == expectedKeys)

        // The challenge is passed through verbatim, not re-encoded.
        #expect(json["challenge"] as? String == "MTIzNDU2Nzg")
        // Opaque blobs use standard base64.
        #expect(json["clientData"] as? String == assertion.clientDataJSON.base64EncodedString())
        #expect(json["signatureData"] as? String == assertion.signature.base64EncodedString())
        #expect(json["authenticatorData"] as? String == assertion.authenticatorData.base64EncodedString())
        // Identifier fields use base64url without padding.
        #expect(json["credentialID"] as? String == "aGVsbG8")
        #expect(json["userHandle"] as? String == "dXNlcg")
        #expect(json["rpId"] as? String == "apple.com")
    }

    /// An absent user handle must be omitted from the JSON entirely rather than
    /// sent as an empty string or null.
    @Test
    func verifyBodyOmitsNilUserHandle() throws {
        let challenge = SecurityKeyChallenge(
            challenge: "MTIzNDU2Nzg",
            allowedCredentials: [Data("hello".utf8)],
            relyingPartyIdentifier: "apple.com"
        )
        let assertion = SecurityKeyAssertion(
            credentialID: Data("hello".utf8),
            clientDataJSON: Data([0x00]),
            authenticatorData: Data([0x00]),
            signature: Data([0x00]),
            userHandle: nil
        )

        let bodyData = try JSONEncoder().encode(SecurityKeyVerifyBody(assertion: assertion, challenge: challenge))
        let json = try #require(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])

        #expect(json["userHandle"] == nil)
    }
}
