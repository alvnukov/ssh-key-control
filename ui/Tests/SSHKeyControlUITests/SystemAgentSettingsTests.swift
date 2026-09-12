import XCTest
@testable import SSHKeyControlUI

final class SystemAgentSettingsTests: XCTestCase {
    private let logoutInstructions = "Save your work, then choose Apple menu > Log Out and sign in again. Closing a terminal or this app is not enough. Open these settings after signing in to verify the result. To restore Apple's agent, turn this setting off before uninstalling SSH Key Control."

    func testSIPPartialDisableExplainsLogoutAndDoesNotClaimStopped() throws {
        let data = Data(#"{"disabled":true,"loaded":true,"running":true,"requiresLogout":true}"#.utf8)
        let state = try JSONDecoder().decode(SystemAgentState.self, from: data)
        XCTAssertEqual(state.title, L10n.string("Startup disabled — sign out to finish"))
        XCTAssertNotEqual(state.title, L10n.string("Apple's SSH agent is disabled"))
        XCTAssertEqual(state.instructions, L10n.string(logoutInstructions))
    }

    func testCompletedDisableExplainsHowToRestore() {
        let state = SystemAgentState(disabled: true, loaded: false, running: false, requiresLogout: false)
        XCTAssertEqual(state.title, L10n.string("Apple's SSH agent is disabled"))
        XCTAssertEqual(state.instructions, L10n.string("To restore Apple's agent, turn this setting off before removing SSH Key Control. If macOS cannot load it immediately, sign out and sign in again."))
    }

    func testPendingRestoreAlsoRequiresLogout() {
        let state = SystemAgentState(disabled: false, loaded: false, running: false, requiresLogout: true)
        XCTAssertEqual(state.title, L10n.string("Startup enabled — sign out to finish"))
        XCTAssertEqual(state.instructions, L10n.string(logoutInstructions))
    }
}
