import Foundation
import Security

/// User-configured HTTP request headers, used to get through an edge
/// authenticator (Cloudflare Access service tokens, an auth-proxy shared
/// secret) that sits in front of hermes-webui.
///
/// # Why not URLProtocol
///
/// The obvious implementation — a `URLProtocol` subclass registered with
/// `URLProtocol.registerClass` — does not work here. `WKWebView` performs its
/// loads in WebKit's separate networking process; `URLProtocol` only sees
/// `URLSession`/`NSURLConnection` traffic originating in the app process, so a
/// registered protocol never observes a single WebView request. (The private
/// `WKBrowsingContextController.registerSchemeForCustomProtocol` hook that
/// would change that is SPI, and does not cover `https` at all.)
///
/// # What this does instead
///
/// Headers are attached to the `URLRequest` of **main-frame GET navigations**
/// — the initial load, reconnects, redirects, and in-app link navigations
/// (see `BrowserWindowController.decidePolicyFor navigationAction`). That is
/// enough for the edge-auth case this feature exists for: Cloudflare Access
/// validates the service-token headers on that first navigation and responds
/// with a `CF_Authorization` cookie, which `WKWebView` then stores and replays
/// on every subsequent subresource, `fetch`, and WebSocket request on its own.
///
/// Sub-resource requests, XHR, and form POSTs are therefore *not* decorated.
/// They do not need to be, and there is no supported API to decorate them.
///
/// # Storage
///
/// Header **names** (and their order) live in `UserDefaults`; header
/// **values** live in the login Keychain, one generic-password item per name.
/// Values are bearer secrets — a Cloudflare Access client secret in
/// `~/Library/Preferences` would be captured by every backup, sync service,
/// and file-scraping process on the machine.
///
/// Note for anyone chasing a Keychain prompt in a local build: the app is
/// ad-hoc signed, so its code identity changes on every rebuild and macOS
/// re-asks for access to items an earlier build created. Signed releases are
/// stable and prompt once.
enum CustomHeaderStore {

    /// A single `Name: Value` header pair.
    struct Header: Equatable {
        let name: String
        let value: String
    }

    /// Why a line in the Preferences editor could not be parsed. Carries the
    /// 1-based line number so the error message can point at it.
    enum ParseError: Error, Equatable {
        case missingColon(line: Int)
        case emptyName(line: Int)
        case invalidName(line: Int, name: String)
        case invalidValue(line: Int, name: String)
        case reservedName(line: Int, name: String)
        case duplicateName(line: Int, name: String)

        var message: String {
            switch self {
            case .missingColon(let line):
                return "Line \(line): expected \"Name: Value\" — no colon found."
            case .emptyName(let line):
                return "Line \(line): the header name is empty."
            case .invalidName(let line, let name):
                return "Line \(line): \"\(name)\" is not a valid header name. "
                    + "Use letters, digits, and - _ . only."
            case .invalidValue(let line, let name):
                return "Line \(line): the value for \"\(name)\" contains characters "
                    + "that are not allowed in a header (control characters or non-ASCII)."
            case .reservedName(let line, let name):
                return "Line \(line): \"\(name)\" is set by WebKit and cannot be overridden."
            case .duplicateName(let line, let name):
                return "Line \(line): \"\(name)\" is listed more than once."
            }
        }
    }

    // MARK: - Validation

    /// Headers WebKit owns. Overriding one is either silently dropped (which
    /// would make `BrowserWindowController` re-issue the same navigation
    /// forever, since it re-issues until the headers it asked for are present)
    /// or actively breaks the load. `User-Agent` is on the list because
    /// `WKWebView.customUserAgent` is the supported way to change it.
    static let reservedNames: Set<String> = [
        "host", "connection", "content-length", "transfer-encoding", "upgrade",
        "keep-alive", "te", "trailer", "expect", "proxy-authorization",
        "proxy-connection", "cookie", "cookie2", "origin", "referer", "user-agent",
    ]

    /// RFC 7230 `token`. Deliberately no CR, LF, colon, or space — those are
    /// what a header-injection payload needs to split the request, and the
    /// hand-rolled HTTP in `ReachabilityProbe` has no framing of its own.
    private static let nameCharacters = CharacterSet(
        charactersIn: "!#$%&'*+-.^_`|~0123456789"
            + "abcdefghijklmnopqrstuvwxyz"
            + "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    static func isValidName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        return name.unicodeScalars.allSatisfy { nameCharacters.contains($0) }
    }

    /// RFC 7230 `field-value`: visible ASCII plus space and horizontal tab.
    /// Empty is valid — a header may legitimately carry an empty value.
    static func isValidValue(_ value: String) -> Bool {
        return value.unicodeScalars.allSatisfy { scalar in
            scalar == "\t" || (scalar.value >= 0x20 && scalar.value <= 0x7E)
        }
    }

    // MARK: - Parsing / serialising the Preferences editor text

    /// Parse the Preferences text view, one `Name: Value` per line. Blank
    /// lines and `#` comments are skipped. Fails on the first bad line rather
    /// than silently dropping it — a typo'd header is the difference between
    /// "authenticated" and "the login page", and it must not fail quietly.
    static func parse(_ text: String) -> Result<[Header], ParseError> {
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

    /// Render headers back into editor text.
    static func serialize(_ headers: [Header]) -> String {
        return headers.map { "\($0.name): \($0.value)" }.joined(separator: "\n")
    }

    // MARK: - Send policy

    static func isLoopbackHost(_ host: String) -> Bool {
        return host == "localhost" || host == "127.0.0.1" || host == "::1"
    }

    /// Whether the configured headers may be sent to `url`.
    ///
    /// Two rules, both about not handing a bearer secret to the wrong party:
    ///
    /// 1. **Host must match the configured target** (or be loopback — the SSH
    ///    tunnel entrance, and traffic that never leaves the machine). Without
    ///    this, following any off-site link in the app would mail the service
    ///    token to a third party.
    /// 2. **Transport must be encrypted**, unless the host is loopback. A
    ///    token on plain http to a remote host is a token on the wire.
    static func shouldSendHeaders(to url: URL, configuredTargetURL: String) -> Bool {
        guard let scheme = url.scheme?.lowercased(),
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

    /// The stored headers that apply to `url`, honouring `shouldSendHeaders`.
    static func headers(for url: URL) -> [Header] {
        return headers(
            load(), for: url,
            configuredTargetURL: UserDefaults.standard.string(forKey: "targetURL") ?? "")
    }

    /// Same policy applied to a caller-supplied set. Preferences uses this to
    /// test the headers currently in the editor against the URL currently in
    /// the field, before either has been saved.
    static func headers(
        _ candidates: [Header], for url: URL, configuredTargetURL: String
    ) -> [Header] {
        guard shouldSendHeaders(to: url, configuredTargetURL: configuredTargetURL)
        else { return [] }
        return candidates
    }

    /// A request for `url` carrying whatever headers apply to it.
    static func request(for url: URL) -> URLRequest {
        var request = URLRequest(url: url)
        for header in headers(for: url) {
            request.setValue(header.value, forHTTPHeaderField: header.name)
        }
        return request
    }

    /// True when `request` already carries every header in `headers` — the
    /// signal that a navigation has already been decorated and must not be
    /// re-issued again.
    static func requestCarries(_ headers: [Header], _ request: URLRequest) -> Bool {
        return headers.allSatisfy { request.value(forHTTPHeaderField: $0.name) == $0.value }
    }

    // MARK: - Persistence

    private static let namesKey = "customHeaderNames"
    private static let keychainService = "com.hermes.HermesAgent.customHeaders"

    /// Keychain reads are not free and can prompt, and `load()` is on the
    /// navigation path. Cached until `save` replaces it.
    ///
    /// Locked because `load()` is reached from two threads: the main thread
    /// (navigation policy, Preferences) and `ReachabilityProbe`'s own queue.
    private static let cacheLock = NSLock()
    private static var cache: [Header]?

    /// The configured headers, in editor order.
    static func load() -> [Header] {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if let cache = cache { return cache }
        let names = UserDefaults.standard.stringArray(forKey: namesKey) ?? []
        let headers = names.compactMap { name -> Header? in
            guard let value = keychainRead(account: name) else { return nil }
            return Header(name: name, value: value)
        }
        cache = headers
        return headers
    }

    /// Replace the stored set. Keychain items for names no longer present are
    /// deleted so a removed token does not linger in the Keychain.
    static func save(_ headers: [Header]) {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        let previous = UserDefaults.standard.stringArray(forKey: namesKey) ?? []
        let names = headers.map { $0.name }
        for stale in previous where !names.contains(stale) {
            keychainDelete(account: stale)
        }
        for header in headers {
            keychainWrite(account: header.name, value: header.value)
        }
        UserDefaults.standard.set(names, forKey: namesKey)
        cache = headers
    }

    // MARK: - Keychain

    private static func keychainQuery(account: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
    }

    private static func keychainRead(account: String) -> String? {
        var query = keychainQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
            let data = item as? Data
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func keychainWrite(account: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }
        let query = keychainQuery(account: account)
        let status = SecItemUpdate(
            query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var insert = query
            insert[kSecValueData as String] = data
            // The values are needed by the health probe on launch, which can
            // run before the user has unlocked anything else.
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            SecItemAdd(insert as CFDictionary, nil)
        }
    }

    private static func keychainDelete(account: String) {
        SecItemDelete(keychainQuery(account: account) as CFDictionary)
    }
}
