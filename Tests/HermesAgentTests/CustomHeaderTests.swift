import XCTest

/// Tests for the custom request-header parsing and send policy in
/// `CustomHeaderStore`.
///
/// As with `ValidationTests.swift`, the helpers below mirror the production
/// logic rather than calling it: the test target has no dependency on the
/// `HermesAgent` executable target, so the rules are duplicated here. If
/// `CustomHeaderStore.parse` / `shouldSendHeaders` change, change these too.
/// (Making this testable directly would mean splitting the pure logic into a
/// library target both targets depend on — worth doing, but not in this PR.)

private struct Header: Equatable {
    let name: String
    let value: String
}

private enum ParseError: Error, Equatable {
    case missingColon(line: Int)
    case emptyName(line: Int)
    case invalidName(line: Int, name: String)
    case invalidValue(line: Int, name: String)
    case reservedName(line: Int, name: String)
    case duplicateName(line: Int, name: String)
}

private let reservedNames: Set<String> = [
    "host", "connection", "content-length", "transfer-encoding", "upgrade",
    "keep-alive", "te", "trailer", "expect", "proxy-authorization",
    "proxy-connection", "cookie", "cookie2", "origin", "referer", "user-agent",
]

private let nameCharacters = CharacterSet(
    charactersIn: "!#$%&'*+-.^_`|~0123456789"
        + "abcdefghijklmnopqrstuvwxyz"
        + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

private func isValidName(_ name: String) -> Bool {
    guard !name.isEmpty else { return false }
    return name.unicodeScalars.allSatisfy { nameCharacters.contains($0) }
}

private func isValidValue(_ value: String) -> Bool {
    return value.unicodeScalars.allSatisfy { scalar in
        scalar == "\t" || (scalar.value >= 0x20 && scalar.value <= 0x7E)
    }
}

private func parse(_ text: String) -> Result<[Header], ParseError> {
    var headers: [Header] = []
    var seen: Set<String> = []
    for (index, rawLine) in text.components(separatedBy: .newlines).enumerated() {
        let lineNumber = index + 1
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") { continue }
        guard let colon = line.firstIndex(of: ":") else {
            return .failure(.missingColon(line: lineNumber))
        }
        let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
        let value = String(line[line.index(after: colon)...])
            .trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return .failure(.emptyName(line: lineNumber)) }
        guard isValidName(name) else {
            return .failure(.invalidName(line: lineNumber, name: name))
        }
        guard !reservedNames.contains(name.lowercased()) else {
            return .failure(.reservedName(line: lineNumber, name: name))
        }
        guard isValidValue(value) else {
            return .failure(.invalidValue(line: lineNumber, name: name))
        }
        guard seen.insert(name.lowercased()).inserted else {
            return .failure(.duplicateName(line: lineNumber, name: name))
        }
        headers.append(Header(name: name, value: value))
    }
    return .success(headers)
}

private func isLoopbackHost(_ host: String) -> Bool {
    return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

private func shouldSendHeaders(to urlString: String, configuredTargetURL: String) -> Bool {
    guard let url = URL(string: urlString),
        let scheme = url.scheme?.lowercased(),
        let host = url.host?.lowercased(), !host.isEmpty
    else { return false }
    let loopback = isLoopbackHost(host)
    guard scheme == "https" || (scheme == "http" && loopback) else { return false }
    if loopback { return true }
    guard let targetHost = URL(string: configuredTargetURL)?.host?.lowercased(),
        !targetHost.isEmpty
    else { return false }
    return host == targetHost
}

// MARK: -

final class CustomHeaderParsingTests: XCTestCase {

    private func parsed(_ text: String) -> [Header] {
        switch parse(text) {
        case .success(let headers): return headers
        case .failure(let error):
            XCTFail("expected success, got \(error)")
            return []
        }
    }

    private func failure(_ text: String) -> ParseError? {
        switch parse(text) {
        case .success(let headers):
            XCTFail("expected failure, parsed \(headers)")
            return nil
        case .failure(let error): return error
        }
    }

    func testCloudflareAccessPair() {
        let headers = parsed(
            "CF-Access-Client-Id: abc123.access\nCF-Access-Client-Secret: s3cr3t")
        XCTAssertEqual(headers, [
            Header(name: "CF-Access-Client-Id", value: "abc123.access"),
            Header(name: "CF-Access-Client-Secret", value: "s3cr3t"),
        ])
    }

    func testSurroundingWhitespaceTrimmed() {
        XCTAssertEqual(
            parsed("   X-Token   :   value here   "),
            [Header(name: "X-Token", value: "value here")])
    }

    func testBlankLinesAndCommentsSkipped() {
        let headers = parsed("\n# an explanation\nX-Token: v\n\n   \n")
        XCTAssertEqual(headers, [Header(name: "X-Token", value: "v")])
    }

    func testEmptyTextIsNoHeaders() {
        XCTAssertEqual(parsed(""), [])
        XCTAssertEqual(parsed("\n\n"), [])
    }

    func testValueMayContainColons() {
        // Only the first colon separates; the rest belong to the value.
        XCTAssertEqual(
            parsed("X-Forwarded-For: [::1]:8080"),
            [Header(name: "X-Forwarded-For", value: "[::1]:8080")])
    }

    func testEmptyValueAccepted() {
        XCTAssertEqual(parsed("X-Token:"), [Header(name: "X-Token", value: "")])
    }

    func testMissingColonRejected() {
        XCTAssertEqual(failure("X-Token value"), .missingColon(line: 1))
    }

    func testEmptyNameRejected() {
        XCTAssertEqual(failure(": value"), .emptyName(line: 1))
    }

    func testLineNumberIsReported() {
        // Line 1 parses, line 2 is blank, line 3 is the bad one.
        XCTAssertEqual(failure("X-A: 1\n\nnope"), .missingColon(line: 3))
    }

    func testSpaceInNameRejected() {
        XCTAssertEqual(
            failure("X Token: v"), .invalidName(line: 1, name: "X Token"))
    }

    func testNonASCIINameRejected() {
        XCTAssertEqual(failure("X-Tökén: v"), .invalidName(line: 1, name: "X-Tökén"))
    }

    func testDuplicateNameRejectedCaseInsensitively() {
        XCTAssertEqual(
            failure("X-Token: a\nx-token: b"),
            .duplicateName(line: 2, name: "x-token"))
    }

    func testReservedNamesRejected() {
        // WebKit owns these; overriding one either gets silently dropped
        // (which would make the navigation re-issue loop) or breaks the load.
        XCTAssertEqual(failure("Host: evil.example"), .reservedName(line: 1, name: "Host"))
        XCTAssertEqual(failure("cookie: a=b"), .reservedName(line: 1, name: "cookie"))
        XCTAssertEqual(
            failure("Content-Length: 0"), .reservedName(line: 1, name: "Content-Length"))
        XCTAssertEqual(
            failure("User-Agent: curl/8"), .reservedName(line: 1, name: "User-Agent"))
    }

    func testNonReservedLookalikesAccepted() {
        XCTAssertEqual(
            parsed("X-Host: a\nCookie-Jar: b"),
            [Header(name: "X-Host", value: "a"), Header(name: "Cookie-Jar", value: "b")])
    }

    // MARK: Header injection

    func testCRAndLFCannotSmuggleARequestLine() {
        // The health probe writes these headers into a hand-rolled HTTP
        // request, so a CR or LF reaching the wire could inject a second
        // request. Both split the input into lines before parsing, and the
        // smuggled remainder then has to stand on its own as a header — this
        // one does not.
        for separator in ["\r", "\n"] {
            XCTAssertEqual(
                failure("X-Token: a\(separator)GET /admin HTTP/1.1"),
                .missingColon(line: 2),
                "expected line split on \(separator.debugDescription)")
        }
        // CRLF splits too; whether Foundation yields a blank line between the
        // two is an implementation detail, so only the rejection is asserted.
        XCTAssertNotNil(failure("X-Token: a\r\nGET /admin HTTP/1.1"))
    }

    func testValuePredicateRejectsCRAndLF() {
        // Line splitting means parse() never hands CR/LF to isValidValue, but
        // the predicate is the invariant ReachabilityProbe relies on — assert
        // it directly so it cannot be loosened by accident.
        XCTAssertFalse(isValidValue("a\rb"))
        XCTAssertFalse(isValidValue("a\nb"))
        XCTAssertTrue(isValidValue("abc123.access"))
    }

    func testNullAndControlCharactersInValueRejected() {
        XCTAssertEqual(failure("X-Token: a\u{0}b"), .invalidValue(line: 1, name: "X-Token"))
        XCTAssertEqual(failure("X-Token: a\u{7}b"), .invalidValue(line: 1, name: "X-Token"))
    }

    func testNonASCIIValueRejected() {
        // Latin-1 header values are legacy and ambiguous on the wire; a token
        // never needs them, and rejecting keeps the probe's UTF-8 encode safe.
        XCTAssertEqual(failure("X-Token: café"), .invalidValue(line: 1, name: "X-Token"))
    }

    func testTabInValueAccepted() {
        XCTAssertEqual(parsed("X-Token: a\tb"), [Header(name: "X-Token", value: "a\tb")])
    }
}

final class CustomHeaderSendPolicyTests: XCTestCase {

    func testSentToConfiguredHTTPSHost() {
        XCTAssertTrue(shouldSendHeaders(
            to: "https://hermes.example.com/chat",
            configuredTargetURL: "https://hermes.example.com"))
    }

    func testNotSentToOtherHosts() {
        // The whole point: following a link off-site must not hand a bearer
        // token to a third party.
        XCTAssertFalse(shouldSendHeaders(
            to: "https://evil.example/collect",
            configuredTargetURL: "https://hermes.example.com"))
    }

    func testNotSentToSubdomainOfConfiguredHost() {
        XCTAssertFalse(shouldSendHeaders(
            to: "https://sub.hermes.example.com/",
            configuredTargetURL: "https://hermes.example.com"))
    }

    func testNotSentOverPlainHTTPToRemoteHost() {
        XCTAssertFalse(shouldSendHeaders(
            to: "http://hermes.example.com/",
            configuredTargetURL: "http://hermes.example.com"))
    }

    func testSentToLoopbackOverPlainHTTP() {
        // The SSH tunnel entrance, and anything else that never leaves the box.
        for target in ["http://127.0.0.1:8787/", "http://localhost:8787/"] {
            XCTAssertTrue(
                shouldSendHeaders(to: target, configuredTargetURL: "https://hermes.example.com"),
                "expected headers for \(target)")
        }
    }

    func testHostComparisonIsCaseInsensitive() {
        XCTAssertTrue(shouldSendHeaders(
            to: "https://Hermes.Example.COM/",
            configuredTargetURL: "https://hermes.example.com"))
    }

    func testPortIsNotPartOfTheHostMatch() {
        // A different port on the same host is the same origin for this
        // purpose — the tunnel and the health probe both move ports around.
        XCTAssertTrue(shouldSendHeaders(
            to: "https://hermes.example.com:8443/",
            configuredTargetURL: "https://hermes.example.com"))
    }

    func testNotSentWhenNoTargetConfigured() {
        XCTAssertFalse(shouldSendHeaders(
            to: "https://hermes.example.com/", configuredTargetURL: ""))
    }

    func testNonHTTPSchemesNeverSend() {
        for target in ["file:///etc/passwd", "ftp://hermes.example.com/",
                       "javascript:alert(1)", "about:blank"] {
            XCTAssertFalse(
                shouldSendHeaders(to: target, configuredTargetURL: "https://hermes.example.com"),
                "expected no headers for \(target)")
        }
    }
}
