import Foundation
import XCTest
@testable import SSHKeyControlUI

final class LocalizationTests: XCTestCase {
    private func bundle(_ language: String) throws -> Bundle {
        let url = try XCTUnwrap(L10n.resources.url(forResource: language, withExtension: "lproj"))
        return try XCTUnwrap(Bundle(url: url))
    }

    private func catalog(_ language: String) throws -> [String: String] {
        let url = try XCTUnwrap(try bundle(language).url(forResource: "Localizable", withExtension: "strings"))
        let plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil)
        return try XCTUnwrap(plist as? [String: String])
    }

    func testRussianCatalogCoversEnglishAndPreservesFormatArguments() throws {
        let english = try catalog("en")
        let russian = try catalog("ru")
        XCTAssertGreaterThan(english.count, 150)
        XCTAssertEqual(Set(english.keys), Set(russian.keys))
        let formats = try NSRegularExpression(pattern: "%(?:@|lld)")
        func arguments(_ text: String) -> [String] {
            let range = NSRange(text.startIndex..., in: text)
            return formats.matches(in: text, range: range).map { (text as NSString).substring(with: $0.range) }
        }
        for (key, value) in english {
            let translated = try XCTUnwrap(russian[key])
            XCTAssertFalse(translated.isEmpty, key)
            XCTAssertEqual(arguments(value), arguments(translated), key)
        }
    }

    func testSystemLanguageNegotiationAndEnglishFallback() {
        let supported = L10n.resources.localizations
        XCTAssertEqual(Bundle.preferredLocalizations(from: supported, forPreferences: ["ru-RU", "en"]).first, "ru")
        XCTAssertEqual(Bundle.preferredLocalizations(from: supported, forPreferences: ["en-GB"]).first, "en")
        XCTAssertEqual(Bundle.preferredLocalizations(from: supported, forPreferences: ["ja"]).first, "en")
    }

    func testRussianSecurityLabelsAndOpaqueData() throws {
        let russian = try bundle("ru")
        XCTAssertEqual(L10n.string("Deny", bundle: russian), "Отклонить")
        XCTAssertEqual(L10n.string("Allow", bundle: russian), "Разрешить")
        let input = "Allow\nKey: SHA256:Exact+/Case\nServer identity: SHA256:Host+/Case\nAccount: ROOT@Prod"
        XCTAssertEqual(L10n.message(input, preservingFirstLine: true, bundle: russian),
                       "Allow\nКлюч: SHA256:Exact+/Case\nОтпечаток сервера: SHA256:Host+/Case\nУчётная запись: ROOT@Prod")
        XCTAssertEqual(L10n.string("/Users/alice/.ssh/ключ", bundle: russian), "/Users/alice/.ssh/ключ")
    }
}
