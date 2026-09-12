import Foundation

struct LifecycleHealth: Decodable, Equatable, Sendable {
    let healthy: Bool
    let agentReady: Bool
    let agentOwned: Bool
    let socketReady: Bool
    let sshConfigured: Bool
    let menuManaged: Bool
    let menuOwned: Bool
    let detail: String?

    enum CodingKeys: String, CodingKey {
        case healthy
        case agentReady = "agent_ready"
        case agentOwned = "agent_owned"
        case socketReady = "socket_ready"
        case sshConfigured = "ssh_configured"
        case menuManaged = "menu_managed"
        case menuOwned = "menu_owned"
        case detail
    }
}

@MainActor
final class LifecycleModel: ObservableObject {
    enum State: Equatable {
        case checking, healthy, needsRepair, repairing, failed
    }

    @Published private(set) var state: State = .checking
    @Published private(set) var detail: String?
    private let run: (AgentSetupOperation, URL) async -> AgentSetupResult

    init(run: @escaping (AgentSetupOperation, URL) async -> AgentSetupResult = {
        await AgentSetupCommand.run($0, bundle: $1)
    }) {
        self.run = run
    }

    func check(bundle: URL = Bundle.main.bundleURL, loginEligible: Bool) async -> Bool {
        state = .checking
        let result = await run(.lifecycle, bundle)
        guard result.succeeded,
              let data = result.details.data(using: .utf8),
              let health = try? JSONDecoder().decode(LifecycleHealth.self, from: data) else {
            state = .failed
            detail = result.details
            return false
        }
        if health.healthy && loginEligible {
            state = .healthy
            detail = nil
            return true
        }
        state = .needsRepair
        detail = L10n.string("SSH Key Control needs recovery")
        return false
    }

    func repair(bundle: URL = Bundle.main.bundleURL) async -> Bool {
        state = .repairing
        let result = await run(.repair, bundle)
        guard result.succeeded else {
            state = .failed
            detail = result.details
            return false
        }
        detail = nil
        return true
    }

    func cancelled() {
        state = .needsRepair
        detail = L10n.string("SSH Key Control is not fully operational. Run recovery when you are ready.")
    }

    func issue(_ message: String) {
        state = .needsRepair
        detail = message
    }
}
