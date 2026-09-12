import Foundation
import XCTest
@testable import SSHKeyControlUI

final class AgentSetupTests: XCTestCase {
    func testOnlyStableApplicationDirectoriesAreAccepted() {
        let home = URL(fileURLWithPath: "/Users/setup-test")
        for path in ["/Applications/SSH Key Control.app", "/Users/setup-test/Applications/SSH Key Control.app"] {
            XCTAssertTrue(AgentSetupLocation.isInstalled(URL(fileURLWithPath: path), home: home), path)
        }
        for path in [
            "/Volumes/SSH Key Control/SSH Key Control.app",
            "/private/var/folders/AppTranslocation/SSH Key Control.app",
            "/Users/setup-test/Downloads/SSH Key Control.app",
            "/Applications-other/SSH Key Control.app",
            "/Applications/Folder/SSH Key Control.app",
            "/Applications/ssh-key-control"
        ] {
            XCTAssertFalse(AgentSetupLocation.isInstalled(URL(fileURLWithPath: path), home: home), path)
        }
    }

    func testSymlinkIntoDiskImageCannotMasqueradeAsInstalledApp() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let home = root.appendingPathComponent("home")
        let applications = home.appendingPathComponent("Applications")
        let image = root.appendingPathComponent("mounted/SSH Key Control.app")
        try FileManager.default.createDirectory(at: applications, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: image, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let link = applications.appendingPathComponent("SSH Key Control.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: image)
        XCTAssertFalse(AgentSetupLocation.isInstalled(link, home: home))
    }

    func testSetupRefusesAnUninstalledBundleBeforeRunningACommand() async {
        let result = await AgentSetupCommand.run(.enable, bundle: URL(fileURLWithPath: "/Volumes/SSH Key Control/SSH Key Control.app"))
        XCTAssertFalse(result.succeeded)
        XCTAssertTrue(result.details.hasPrefix(L10n.format("Setup could not run. Keep a complete copy of SSH Key Control in Applications. %@", "")))
    }

    func testSetupRequiresTheBundledMenuBarExecutable() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let home = root.appendingPathComponent("home", isDirectory: true)
        let bundle = home.appendingPathComponent("Applications/SSH Key Control.app", isDirectory: true)
        let executables = bundle.appendingPathComponent("Contents/MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: executables, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        for name in ["ssh-key-control", "ssh-key-control-ui"] {
            let file = executables.appendingPathComponent(name)
            try Data("fixture".utf8).write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: file.path)
        }
        XCTAssertThrowsError(try AgentSetupLocation.executable(in: bundle, home: home))
    }
}
