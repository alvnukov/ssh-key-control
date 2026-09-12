import AppKit
import XCTest
@testable import SSHKeyControlUI

final class SecurityHistoryTests: XCTestCase {
    func testJournalDecodingAndRetention() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("history.json")
        let current = ISO8601DateFormatter().string(from: Date())
        let data = """
        {"version":1,"events":[
          {"id":1,"time":"2020-01-01T00:00:00Z","kind":"decision","outcome":"denied"},
          {"id":2,"time":"\(current)","kind":"decision","outcome":"approved","source":"cached","keyFingerprint":"SHA256:key","hostFingerprint":"SHA256:server","user":"alice","scope":"timed-approval","expiresAt":"2099-01-01T12:00:00.123456789Z"},
          {"id":3,"time":"\(current)","kind":"decision","outcome":"denied","source":"prompt","keyFingerprint":"SHA256:key"}
        ]}
        """
        try Data(data.utf8).write(to: file)
        let events = try HistoryFiles.load(at: file, policy: HistoryPolicy())
        XCTAssertEqual(events.map(\.id), [3, 2])
        XCTAssertFalse(events[0].isVerified)
        XCTAssertTrue(events[1].isVerified)
        XCTAssertEqual(events[1].source, "cached")
        XCTAssertNotNil(events[1].expiresAt)
    }

    func testPolicyPersistsPrivatelyAndValidatesUnsupportedValues() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("history-settings.json")
        try HistoryFiles.savePolicy(HistoryPolicy(retentionDays: 30, maxEvents: 250), at: file)
        XCTAssertEqual(HistoryFiles.readPolicy(at: file), HistoryPolicy(retentionDays: 30, maxEvents: 250))
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual(HistoryPolicy(retentionDays: -1, maxEvents: 9999999).validated, HistoryPolicy())
    }

    func testJournalRejectsSymlinkAndOversizedFile() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("target")
        let link = dir.appendingPathComponent("link")
        try Data(repeating: 65, count: 20).write(to: target)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try HistoryFiles.boundedRead(link, limit: 100))
        XCTAssertThrowsError(try HistoryFiles.boundedRead(target, limit: 10))
    }

    @MainActor func testOriginalMenuImageIsATemplateWithAccessibleName() {
        let image = AppIdentity.menuImage()
        XCTAssertTrue(image.isTemplate)
        XCTAssertEqual(image.size, NSSize(width: 20, height: 18))
        XCTAssertEqual(image.accessibilityDescription, "SSH Key Control")
        XCTAssertNotNil(image.cgImage(forProposedRect: nil, context: nil, hints: nil))
    }
}
