import Foundation
import XCTest

@testable import SSHKeyControlUI

final class ProtocolTests: XCTestCase {
    func testDecodeRequest() throws {
        let line = Data(#"{"op":"secret","title":"T","message":"M","remember":{"label":"Keep"}}"#.utf8)
        let req = try Wire.decode(line)
        XCTAssertEqual(
            req,
            Request(op: .secret, title: "T", message: "M", remember: .init(label: "Keep")))
    }

    func testDecodeKeychainOps() throws {
        XCTAssertEqual(try Wire.decode(Data(#"{"op":"keychain.get","account":"a"}"#.utf8)).op, .keychainGet)
        XCTAssertEqual(try Wire.decode(Data(#"{"op":"keychain.set","account":"a","secret":"s"}"#.utf8)).secret, "s")
        XCTAssertEqual(try Wire.decode(Data(#"{"op":"keychain.delete","account":"a"}"#.utf8)).op, .keychainDelete)
    }

    func testDecodeRejectsUnknownOp() {
        XCTAssertThrowsError(try Wire.decode(Data(#"{"op":"dance"}"#.utf8)))
        XCTAssertThrowsError(try Wire.decode(Data("not json".utf8)))
    }

    func testEncodeResponse() {
        XCTAssertEqual(
            String(decoding: Wire.encode(.success(answer: "x", remember: true)), as: UTF8.self),
            #"{"answer":"x","ok":true,"remember":true}"# + "\n")
        XCTAssertEqual(
            String(decoding: Wire.encode(.success()), as: UTF8.self),
            #"{"ok":true}"# + "\n")
        XCTAssertEqual(
            String(decoding: Wire.encode(.failure(.cancelled)), as: UTF8.self),
            #"{"error":"cancelled","ok":false}"# + "\n")
        XCTAssertEqual(
            String(decoding: Wire.encode(.failure(.other("a/b"))), as: UTF8.self),
            #"{"error":"a/b","ok":false}"# + "\n")
    }

    func testFailureWire() {
        XCTAssertEqual(Failure.cancelled.wire, "cancelled")
        XCTAssertEqual(Failure.notFound.wire, "not-found")
        XCTAssertEqual(Failure.denied.wire, "denied")
        XCTAssertEqual(Failure.other("").wire, "failed")
        XCTAssertEqual(Response.failure(Failure.denied as any Error).error, "denied")
    }

    func testLineSplitter() {
        var s = LineSplitter()
        XCTAssertEqual(s.feed(Data("ab".utf8)), [])
        XCTAssertEqual(s.feed(Data("c\nde\n\nf".utf8)), [Data("abc".utf8), Data("de".utf8), Data()])
        XCTAssertEqual(s.flush(), Data("f".utf8))
        XCTAssertNil(s.flush())
    }

    @MainActor
    func testProcess() {
        let good = LineServer.process(Data(#"{"op":"confirm"}"#.utf8)) { req in
            .success(answer: req.op.rawValue)
        }
        XCTAssertEqual(String(decoding: good, as: UTF8.self), #"{"answer":"confirm","ok":true}"# + "\n")
        let bad = LineServer.process(Data("{".utf8)) { _ in .success() }
        XCTAssertTrue(String(decoding: bad, as: UTF8.self).hasPrefix(#"{"error":"bad request: "#))
    }
}
