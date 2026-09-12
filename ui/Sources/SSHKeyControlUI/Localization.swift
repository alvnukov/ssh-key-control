import Foundation

enum L10n {
    // SwiftPM's generated accessor looks beside the executable or in the build
    // tree. Distributed apps keep their bundle in Contents/Resources instead.
    static let resources: Bundle = {
        if let url = Bundle.main.resourceURL?.appendingPathComponent("ssh-key-control-ui_SSHKeyControlUI.bundle"),
           let bundle = Bundle(url: url) {
            return bundle
        }
        return .module
    }()

    // Command-line helpers have no main-bundle localizations. Negotiate from
    // this catalog explicitly so they follow the same macOS preference as the app.
    static let localizedResources: Bundle = {
        let language = Bundle.preferredLocalizations(from: resources.localizations,
                                                     forPreferences: Locale.preferredLanguages).first ?? "en"
        guard let url = resources.url(forResource: language, withExtension: "lproj"),
              let bundle = Bundle(url: url) else { return resources }
        return bundle
    }()

    static func string(_ key: String, bundle: Bundle = localizedResources) -> String {
        bundle.localizedString(forKey: key, value: key, table: nil)
    }

    // Translate known labels while retaining fingerprints, paths and accounts verbatim.
    static func message(_ text: String, preservingFirstLine: Bool = false, bundle: Bundle = localizedResources) -> String {
        text.components(separatedBy: "\n").enumerated().map { index, line in
            if preservingFirstLine && index == 0 { return line }
            for prefix in ["Key: ", "Server identity: ", "Account: "] {
                if line.hasPrefix(prefix) {
                    return format(prefix + "%@", String(line.dropFirst(prefix.count)), bundle: bundle)
                }
            }
            return string(line, bundle: bundle)
        }.joined(separator: "\n")
    }

    static func format(_ key: String, _ arguments: CVarArg..., bundle: Bundle = localizedResources) -> String {
        String(format: string(key, bundle: bundle), locale: Locale.current, arguments: arguments)
    }
}
