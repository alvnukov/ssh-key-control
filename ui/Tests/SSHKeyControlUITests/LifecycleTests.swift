import Foundation
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class LifecycleTests: XCTestCase {
    func testLegacyLoginApprovalDistinguishesDeniedFromEnabled() {
        XCTAssertEqual(
            LoginItemModel.approval(for: [.enabled, .enabled]),
            LoginItemModel.Approval(enabled: true, needsApproval: false)
        )
        XCTAssertEqual(
            LoginItemModel.approval(for: [.enabled, .requiresApproval]),
            LoginItemModel.Approval(enabled: false, needsApproval: true)
        )
        XCTAssertEqual(
            LoginItemModel.approval(for: [.notFound, .notRegistered]),
            LoginItemModel.Approval(enabled: false, needsApproval: false)
        )
    }

    func testDeniedLoginItemBlocksInstallBeforeItRuns() {
        let denied = LoginItemModel.Approval(enabled: false, needsApproval: true)
        XCTAssertTrue(AgentSetupModel.blockedByLoginItems(.enable, approval: denied))
        XCTAssertFalse(AgentSetupModel.blockedByLoginItems(.remove, approval: denied))
    }

    func testBrokenPreflightCanBeDeclinedWithoutRunningRepair() async {
        var operations: [AgentSetupOperation] = []
        let model = LifecycleModel { operation, _ in
            operations.append(operation)
            return AgentSetupResult(
                succeeded: true,
                details: #"{"healthy":false,"agent_ready":false,"agent_owned":false,"socket_ready":false,"ssh_configured":true,"menu_managed":false,"menu_owned":false,"detail":"not ready"}"#
            )
        }

        let healthy = await model.check(bundle: URL(fileURLWithPath: "/Applications/SSH Key Control.app"), loginEligible: false)
        XCTAssertFalse(healthy)
        model.cancelled()

        XCTAssertEqual(operations, [.lifecycle])
        XCTAssertEqual(model.state, .needsRepair)
        XCTAssertNotNil(model.detail)
    }

    func testRepairFailureRemainsVisibleAndRetryable() async {
        let model = LifecycleModel { operation, _ in
            XCTAssertEqual(operation, .repair)
            return AgentSetupResult(succeeded: false, details: "launchd refused repair")
        }

        let repaired = await model.repair(bundle: URL(fileURLWithPath: "/Applications/SSH Key Control.app"))
        XCTAssertFalse(repaired)
        XCTAssertEqual(model.state, .failed)
        XCTAssertEqual(model.detail, "launchd refused repair")
    }
}
