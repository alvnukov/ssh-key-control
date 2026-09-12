import Foundation
import XCTest
@testable import SSHKeyControlUI

final class ApplicationInstanceLockTests: XCTestCase {
    func testOrdinaryLaunchDoesNotCreateASecondInstance() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("menu.lock")
        let first = try XCTUnwrap(ApplicationInstanceLock.acquire(at: url, wait: false))
        XCTAssertNil(try ApplicationInstanceLock.acquire(at: url, wait: false))
        withExtendedLifetime(first) {}
    }

    func testManagedLaunchWaitsForCurrentInstanceThenTakesOver() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
            .appendingPathComponent("menu.lock")
        var first: ApplicationInstanceLock? = try XCTUnwrap(ApplicationInstanceLock.acquire(at: url, wait: false))
        XCTAssertNotNil(first)
        let acquired = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            let second = try! ApplicationInstanceLock.acquire(at: url, wait: true)
            XCTAssertNotNil(second)
            acquired.signal()
            withExtendedLifetime(second) {}
        }
        XCTAssertEqual(acquired.wait(timeout: .now() + 0.1), .timedOut)
        first = nil
        XCTAssertEqual(acquired.wait(timeout: .now() + 2), .success)
    }
}
