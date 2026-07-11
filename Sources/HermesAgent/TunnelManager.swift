import Foundation

enum TunnelStatus {
    case connecting
    case connected
    case disconnected
}

/// Outcome of a non-interactive `ssh … exit` authentication test.
enum SSHAuthResult {
    /// Logged in and back out — TCP, SSH protocol, host key, and key auth
    /// all work: everything the tunnel needs.
    case authenticated
    /// The host speaks SSH but refused our keys. Fix is ssh-copy-id.
    case authFailed
    /// Nothing usable at host:22 — refused, timed out, or DNS failure.
    case unreachable
}

class TunnelManager {
    private var process: Process?
    private let user: String
    private let host: String
    private let localPort: Int
    private let remoteHost: String
    private let remotePort: Int

    var onStatusChange: ((TunnelStatus) -> Void)?
    private(set) var status: TunnelStatus = .connecting
    private var monitorTimer: Timer?

    init(user: String, host: String, localPort: Int, remoteHost: String, remotePort: Int) {
        self.user = user
        self.host = host
        self.localPort = localPort
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }

    /// True when a value is safe to pass to ssh as part of the user@host
    /// target. ssh parses any argument beginning with "-" as an option, so a
    /// username like "-oProxyCommand=…" would smuggle options into the
    /// invocation (and ProxyCommand runs shell commands). Neither field can
    /// legitimately contain whitespace.
    static func isValidSSHIdentifier(_ value: String) -> Bool {
        return !value.isEmpty
            && !value.hasPrefix("-")
            && value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
    }

    /// Verify the tunnel could be established with these credentials by
    /// running a real login: `ssh -o BatchMode=yes user@host exit`.
    /// BatchMode forbids password prompts, so this can never hang on input;
    /// StrictHostKeyChecking=accept-new matches start() so the test exercises
    /// the same host-key path the tunnel will. Completion fires once, on a
    /// background queue.
    static func testAuth(
        user: String, host: String, timeout: TimeInterval = 6.0,
        completion: @escaping (SSHAuthResult) -> Void
    ) {
        guard isValidSSHIdentifier(user), isValidSSHIdentifier(host) else {
            completion(.unreachable)
            return
        }
        DispatchQueue.global().async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            p.arguments = [
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=\(Int(timeout))",
                "-o", "StrictHostKeyChecking=accept-new",
                "\(user)@\(host)",
                "exit",
            ]
            let errPipe = Pipe()
            p.standardError = errPipe
            p.standardOutput = Pipe()
            do {
                try p.run()
            } catch {
                completion(.unreachable)
                return
            }
            // Watchdog: ConnectTimeout only bounds the TCP phase; a stalled
            // key exchange could hold the process open past it.
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout + 2.0) {
                if p.isRunning { p.terminate() }
            }
            p.waitUntilExit()
            let stderr = String(
                data: errPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8) ?? ""
            completion(Self.classifyAuthAttempt(
                exitStatus: p.terminationStatus, stderr: stderr))
        }
    }

    /// "Permission denied" is sshd's auth-rejection message — reaching it
    /// means the whole transport worked and only our key was refused.
    /// Any other nonzero outcome (refused, timed out, DNS, host key
    /// mismatch, watchdog kill) means we never got a usable SSH session.
    static func classifyAuthAttempt(exitStatus: Int32, stderr: String) -> SSHAuthResult {
        if exitStatus == 0 { return .authenticated }
        if stderr.contains("Permission denied") { return .authFailed }
        return .unreachable
    }

    /// Outcome of an ephemeral end-to-end forward test (testForward).
    enum ForwardTestResult {
        /// Temporary tunnel came up and /health verified through it.
        case healthy
        /// Tunnel established, but /health didn't verify through it —
        /// hermes down on the remote loopback, or not a hermes at all.
        case reachableNoHealth
        /// The local port is already taken on this Mac.
        case localPortBusy
        /// The forward never became usable.
        case forwardFailed
    }

    /// Bring up a temporary `ssh -N -L` with these exact settings, probe
    /// hermes' /health through it, then tear it down. Callers verify auth
    /// first (testAuth) so a failure here means "the forward", not "the
    /// login". Completion fires once, on a background queue.
    static func testForward(
        user: String, host: String, localPort: Int, remotePort: Int,
        timeout: TimeInterval = 10.0,
        completion: @escaping (ForwardTestResult) -> Void
    ) {
        guard isValidSSHIdentifier(user), isValidSSHIdentifier(host) else {
            completion(.forwardFailed)
            return
        }
        DispatchQueue.global().async {
            guard localPortIsFree(localPort) else {
                completion(.localPortBusy)
                return
            }
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            p.arguments = [
                "-N",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=\(Int(timeout))",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ExitOnForwardFailure=yes",
                "-L", "\(localPort):127.0.0.1:\(remotePort)",
                "\(user)@\(host)",
            ]
            let errPipe = Pipe()
            p.standardError = errPipe
            p.standardOutput = Pipe()
            do {
                try p.run()
            } catch {
                completion(.forwardFailed)
                return
            }
            defer {
                if p.isRunning { p.terminate() }
            }
            // Probe /health through the forward until something answers or
            // time runs out. ssh accepts local connections as soon as the
            // bind succeeds, so the probe outcome reflects the remote side.
            let deadline = Date().addingTimeInterval(timeout)
            var result = ForwardTestResult.forwardFailed
            while Date() < deadline {
                if !p.isRunning {
                    // Died on its own (ExitOnForwardFailure, auth hiccup, …)
                    let stderr = String(
                        data: errPipe.fileHandleForReading.readDataToEndOfFile(),
                        encoding: .utf8) ?? ""
                    result = stderr.contains("Address already in use")
                        ? .localPortBusy : .forwardFailed
                    break
                }
                let semaphore = DispatchSemaphore(value: 0)
                var outcome = HealthProbeResult.unreachable
                ReachabilityProbe.probeHealth(
                    urlString: "http://127.0.0.1:\(localPort)", timeout: 1.5
                ) {
                    outcome = $0
                    semaphore.signal()
                }
                semaphore.wait()
                if outcome == .healthy {
                    result = .healthy
                    break
                }
                if outcome == .reachable {
                    result = .reachableNoHealth
                    break
                }
                Thread.sleep(forTimeInterval: 0.4)
            }
            completion(result)
        }
    }

    /// A loopback port the OS says is free right now (bind :0, read back the
    /// assignment). Lets Test Connection route a test forward around a port
    /// the app's own live tunnel is holding.
    static func freeEphemeralPort() -> Int? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { return nil }
        var assigned = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &assigned) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard ok == 0 else { return nil }
        let port = Int(UInt16(bigEndian: assigned.sin_port))
        return port > 0 ? port : nil
    }

    /// True if 127.0.0.1:port can be bound right now. Checked before the
    /// forward test launches ssh, so an unrelated local listener on the
    /// port is reported as "busy" instead of being probed as if it were
    /// the tunnel.
    private static func localPortIsFree(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return true }
        defer { close(fd) }
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return bound == 0
    }

    func start(onReady: @escaping () -> Void) {
        setStatus(.connecting)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = [
            "-N",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ExitOnForwardFailure=yes",
            "-L", "\(localPort):\(remoteHost):\(remotePort)",
            "\(user)@\(host)",
        ]

        let pipe = Pipe()
        p.standardError = pipe

        // Detect if process dies unexpectedly
        p.terminationHandler = { [weak self] process in
            guard let self = self else { return }
            if process.terminationReason == .exit && process.terminationStatus != 0 {
                DispatchQueue.main.async {
                    self.setStatus(.disconnected)
                }
            }
        }

        do {
            try p.run()
            self.process = p
            print("SSH tunnel started (pid \(p.processIdentifier))")
        } catch {
            print("Failed to start SSH: \(error)")
            setStatus(.disconnected)
            onReady()
            return
        }

        DispatchQueue.global().async { [weak self] in
            guard let self = self else { return }
            let connected = self.waitForPortForward(timeout: 5.0, interval: 0.5)
            DispatchQueue.main.async {
                if connected {
                    self.setStatus(.connected)
                    self.startMonitoring()
                } else {
                    self.setStatus(.disconnected)
                }
                onReady()
            }
        }
    }

    func stop() {
        monitorTimer?.invalidate()
        monitorTimer = nil
        guard let p = process else { return }
        let pid = p.processIdentifier
        p.terminate()
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
            if p.isRunning { kill(pid, SIGKILL) }
        }
        process = nil
    }

    private func startMonitoring() {
        monitorTimer?.invalidate()
        monitorTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) {
            [weak self] _ in
            guard let self = self, let p = self.process else { return }
            if !p.isRunning {
                self.setStatus(.disconnected)
                self.monitorTimer?.invalidate()
            }
        }
    }

    private func waitForPortForward(timeout: TimeInterval = 8.0, interval: TimeInterval = 0.5)
        -> Bool
    {
        // A local TCP connect only proves ssh is holding the port — ssh always
        // accepts immediately, even when the far end of the forward is broken
        // (e.g. the remote service isn't running, or localhost-on-remote
        // resolves to an address nothing is bound to). An HTTP round-trip is
        // what actually tells us the tunnel is usable.
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if process?.isRunning != true {
                return false
            }
            if httpProbeSucceeds(port: localPort, timeout: 1.5) {
                return true
            }
            Thread.sleep(forTimeInterval: interval)
        }
        return false
    }

    private func httpProbeSucceeds(port: Int, timeout: TimeInterval) -> Bool {
        guard let url = URL(string: "http://127.0.0.1:\(port)/") else { return false }
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "GET"

        let semaphore = DispatchSemaphore(value: 0)
        var reachable = false
        let task = URLSession.shared.dataTask(with: request) { _, response, _ in
            // Any HTTP response (including 4xx/5xx) means the tunnel delivered
            // bytes end-to-end — that's what we're verifying here.
            if response is HTTPURLResponse { reachable = true }
            semaphore.signal()
        }
        task.resume()
        if semaphore.wait(timeout: .now() + timeout + 0.5) == .timedOut {
            task.cancel()
            return false
        }
        return reachable
    }

    private func setStatus(_ newStatus: TunnelStatus) {
        status = newStatus
        onStatusChange?(newStatus)
    }
}
