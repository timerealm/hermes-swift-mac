import Foundation
import Network

/// ATS-free /health check over Network.framework.
///
/// URLSession enforces App Transport Security: with NSAllowsArbitraryLoads
/// false (our Info.plist), plain-http requests to non-loopback hosts are
/// rejected with -1022 — even ones the WKWebView (exempt via
/// NSAllowsArbitraryLoadsInWebContent) can load fine. Network.framework is
/// not subject to ATS, so the HTTP GET is hand-rolled over NWConnection
/// (TLS parameters for https). It speaks real HTTP to hermes-webui's /health
/// route rather than just connecting: a bare TCP connect can't distinguish a
/// healthy hermes from a reverse proxy answering for a dead backend.

/// Result of a `/health` probe, ordered by how much it verifies.
enum HealthProbeResult {
    /// The endpoint answered `/health` with 2xx and a hermes-shaped body
    /// (`"status": "ok"`). It really is a hermes server.
    case healthy
    /// Something is accepting connections at host:port, but `/health` did not
    /// verify — e.g. a misbehaving reverse proxy in front of a dead backend,
    /// a non-hermes service, or a non-2xx/garbled response.
    case reachable
    /// TCP connect failed or timed out.
    case unreachable
}

enum ReachabilityProbe {

    /// Probe an http(s) URL's `/health` endpoint. Completion fires exactly
    /// once, on an arbitrary queue — callers hop to main themselves.
    static func probeHealth(
        urlString: String, timeout: TimeInterval = 4.0,
        completion: @escaping (HealthProbeResult) -> Void
    ) {
        guard let url = URL(string: urlString),
            let host = url.host, !host.isEmpty
        else {
            completion(.unreachable)
            return
        }
        let scheme = url.scheme?.lowercased() ?? "http"
        let port = url.port ?? (scheme == "https" ? 443 : 80)
        guard (1...65535).contains(port),
            let nwPort = NWEndpoint.Port(rawValue: UInt16(port))
        else {
            completion(.unreachable)
            return
        }

        let connection = NWConnection(
            host: NWEndpoint.Host(host), port: nwPort,
            using: scheme == "https" ? .tls : .tcp)
        let queue = DispatchQueue(label: "hermes.health.probe")
        var finished = false
        var connected = false
        var received = Data()
        func finish(_ result: HealthProbeResult) {
            guard !finished else { return }
            finished = true
            connection.cancel()
            completion(result)
        }
        func receiveLoop() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) {
                data, _, isComplete, error in
                if let data = data { received.append(data) }
                if isComplete || error != nil || received.count > 256 * 1024 {
                    finish(classifyHealthResponse(received))
                } else {
                    receiveLoop()
                }
            }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                connected = true
                // Percent-ENCODED path: URL.path percent-decodes, which would
                // let encoded CR/LF in the configured URL reshape the
                // hand-rolled request below.
                let base = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                    .percentEncodedPath ?? ""
                let path = base.isEmpty || base == "/"
                    ? "/health"
                    : (base.hasSuffix("/") ? base + "health" : base + "/health")
                let request = "GET \(path) HTTP/1.1\r\n"
                    + "Host: \(host)\r\n"
                    + "Accept: application/json\r\n"
                    + "Connection: close\r\n\r\n"
                connection.send(
                    content: request.data(using: .utf8),
                    completion: .contentProcessed { error in
                        // TCP connected but the write died — port is open,
                        // health unverifiable.
                        if error != nil { finish(.reachable) }
                    })
                receiveLoop()
            case .failed, .cancelled:
                finish(connected ? .reachable : .unreachable)
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) {
            // Ran out of time: connected-with-partial-data still classifies
            // (the status line usually arrives first); never-connected is dead.
            if connected {
                finish(classifyHealthResponse(received))
            } else {
                finish(.unreachable)
            }
        }
    }

    /// Classify a raw HTTP/1.x response to `GET /health`: 2xx plus a body
    /// carrying `"status"` and `"ok"` is a verified hermes. Substring match
    /// rather than JSON parse so a chunked transfer encoding (chunk-size
    /// markers interleaved with the body) still classifies correctly.
    static func classifyHealthResponse(_ raw: Data) -> HealthProbeResult {
        guard !raw.isEmpty,
            let text = String(data: raw, encoding: .utf8),
            let statusLineEnd = text.range(of: "\r\n")
        else { return .reachable }
        let statusParts = text[..<statusLineEnd.lowerBound].split(separator: " ")
        guard statusParts.count >= 2,
            statusParts[0].hasPrefix("HTTP/"),
            let code = Int(statusParts[1]),
            (200...299).contains(code),
            let headerEnd = text.range(of: "\r\n\r\n")
        else { return .reachable }
        let body = text[headerEnd.upperBound...]
        return body.contains("\"status\"") && body.contains("\"ok\"")
            ? .healthy : .reachable
    }

}
