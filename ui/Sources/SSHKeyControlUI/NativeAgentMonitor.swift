import AppKit
import Foundation
import SwiftUI
import UserNotifications

enum MonitorNotificationPermission: Equatable {
    case notDetermined, denied, allowed
}
@MainActor
protocol MonitorNotifications {
    func permission() async -> MonitorNotificationPermission
    func requestPermission() async throws -> Bool
    func send(id: String, removed: UInt64, failed: UInt64) async throws
    func sendTest(id: String) async throws
}
private final class MonitorNotificationDelegate: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }
}
@MainActor
final class MacMonitorNotifications: MonitorNotifications {
    private let delegate = MonitorNotificationDelegate()
    func permission() async -> MonitorNotificationPermission {
        let center = UNUserNotificationCenter.current()
        center.delegate = delegate
        switch await center.notificationSettings().authorizationStatus {
        case .notDetermined: return .notDetermined
        case .authorized, .provisional, .ephemeral: return .allowed
        default: return .denied
        }
    }
    func requestPermission() async throws -> Bool {
        try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
    }
    func send(id: String, removed: UInt64, failed: UInt64) async throws {
        try await submit(id: id, title: L10n.string("System SSH agent monitoring"),
                         body: L10n.format("Removed from memory: %lld. Removal or monitoring failures: %lld. See Security History for fingerprints and details.", removed, failed))
    }
    func sendTest(id: String) async throws {
        try await submit(id: id, title: L10n.string("SSH Key Control test notification"),
                         body: L10n.string("System notifications help report keys found in the system SSH agent."))
    }
    private func submit(id: String, title: String, body: String) async throws {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }
}

struct NativeMonitorPolicy: Codable, Equatable, Sendable { var enabled = true }
struct NativeMonitorState: Decodable, Sendable {
    let enabled: Bool
    let session: String
    let checkedAt: Date
    let status: String
    let removed: UInt64
    let failed: UInt64
    func isFresh(at now: Date) -> Bool { now.timeIntervalSince(checkedAt) >= -2 && now.timeIntervalSince(checkedAt) < 12 }
}
enum NativeMonitorFiles {
    static var policyURL: URL { HistoryFiles.directory.appendingPathComponent("native-agent-monitor.json") }
    static var stateURL: URL { HistoryFiles.directory.appendingPathComponent("native-agent-monitor-state.json") }
    static func policy(at url: URL = policyURL) throws -> NativeMonitorPolicy {
        if !FileManager.default.fileExists(atPath: url.path) { return NativeMonitorPolicy() }
        return try JSONDecoder().decode(NativeMonitorPolicy.self, from: HistoryFiles.boundedRead(url, limit: 8192))
    }
    static func state(at url: URL = stateURL) throws -> NativeMonitorState {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: text) { return date }
            formatter.formatOptions = [.withInternetDateTime]
            guard let date = formatter.date(from: text) else { throw CocoaError(.fileReadCorruptFile) }
            return date
        }
        return try decoder.decode(NativeMonitorState.self, from: HistoryFiles.boundedRead(url, limit: 8192))
    }
    static func save(_ policy: NativeMonitorPolicy, at url: URL = policyURL) throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let values = try dir.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else { throw CocoaError(.fileWriteInvalidFileName) }
        let data = try JSONEncoder().encode(policy)
        let temp = dir.appendingPathComponent(".monitor-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: temp) }
        guard FileManager.default.createFile(atPath: temp.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        if rename(temp.path, url.path) != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}
struct MonitorNotificationCursor: Codable, Equatable {
    var session = ""
    var removed: UInt64 = 0
    var failed: UInt64 = 0
}

@MainActor
final class NativeAgentMonitorModel: ObservableObject {
    static let shared = NativeAgentMonitorModel()
    @Published private(set) var enabled = true
    @Published private(set) var state: NativeMonitorState?
    @Published private(set) var error: String?
    @Published private(set) var notificationPermission: MonitorNotificationPermission = .notDetermined
    @Published private(set) var notificationError: String?
    @Published private(set) var sendingTestNotification = false
    @Published private(set) var testNotificationFeedback: String?
    @Published private(set) var testNotificationFailed = false
    private var lastTestAttempt = Date.distantPast
    private var testFeedbackTask: Task<Void, Never>?
    private let notifications: any MonitorNotifications
    private let defaults: UserDefaults
    private let readPolicy: () throws -> NativeMonitorPolicy
    private let writePolicy: (NativeMonitorPolicy) throws -> Void
    private let readState: () throws -> NativeMonitorState
    private var task: Task<Void, Never>?
    private var refreshing = false
    private var requestedPermission = false
    private(set) var permissionRequest: Task<Void, Never>?
    private var cursor: MonitorNotificationCursor
    private var lastNotification = Date.distantPast
    private static let cursorKey = "nativeAgentMonitor.notificationCursor"

    init(notifications: any MonitorNotifications = MacMonitorNotifications(), defaults: UserDefaults = .standard,
         readPolicy: @escaping () throws -> NativeMonitorPolicy = { try NativeMonitorFiles.policy() },
         writePolicy: @escaping (NativeMonitorPolicy) throws -> Void = { try NativeMonitorFiles.save($0) },
         readState: @escaping () throws -> NativeMonitorState = { try NativeMonitorFiles.state() }) {
        self.notifications = notifications; self.defaults = defaults
        self.readPolicy = readPolicy; self.writePolicy = writePolicy; self.readState = readState
        cursor = defaults.data(forKey: Self.cursorKey).flatMap { try? JSONDecoder().decode(MonitorNotificationCursor.self, from: $0) }
            ?? MonitorNotificationCursor()
    }
    func start() {
        guard task == nil else { return }
        task = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
    func stop() { task?.cancel(); task = nil }
    func setEnabled(_ value: Bool) {
        do {
            try writePolicy(NativeMonitorPolicy(enabled: value))
            enabled = value; error = nil
            if !value, let state { acknowledge(state) }
            Task { await refresh() }
        } catch { self.error = L10n.string("The monitoring setting could not be saved.") }
    }
    func refresh(now: Date = Date()) async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        do { enabled = try readPolicy().enabled; error = nil }
        catch { self.error = L10n.string("The monitoring setting could not be read."); state = nil; return }
        state = try? readState()
        notificationPermission = await notifications.permission()
        guard enabled else { if let state { acknowledge(state) }; return }
        if notificationPermission == .notDetermined && !requestedPermission {
            _ = beginPermissionRequest()
        }
        // User may turn monitoring off while a system permission sheet is open.
        guard enabled, let state else { return }
        if cursor.session != state.session { cursor = MonitorNotificationCursor(session: state.session) }
        let removed = state.removed >= cursor.removed ? state.removed - cursor.removed : state.removed
        let failed = state.failed >= cursor.failed ? state.failed - cursor.failed : state.failed
        guard removed > 0 || failed > 0, notificationPermission == .allowed,
              now.timeIntervalSince(lastNotification) >= 30 else { return }
        lastNotification = now
        do {
            try await notifications.send(id: "native-agent-\(state.session)-\(state.removed)-\(state.failed)", removed: removed, failed: failed)
            notificationError = nil
            acknowledge(state)
        } catch { notificationError = L10n.string("The macOS notification could not be submitted. See Security History.") }
    }
    private func beginPermissionRequest() -> Task<Void, Never> {
        if let permissionRequest { return permissionRequest }
        requestedPermission = true
        let request = Task { [weak self] in
            guard let self else { return }
            defer { permissionRequest = nil }
            do {
                _ = try await notifications.requestPermission()
                notificationPermission = await notifications.permission()
                notificationError = nil
            } catch { notificationError = L10n.string("macOS notification permission could not be requested.") }
        }
        permissionRequest = request
        return request
    }

    /// A user-requested notification test is independent of monitoring and its
    /// journal/counters. It never acknowledges a real incident.
    func sendTestNotification(now: Date = Date()) async {
        guard !sendingTestNotification, now.timeIntervalSince(lastTestAttempt) >= 2 else { return }
        lastTestAttempt = now
        sendingTestNotification = true
        testNotificationFeedback = nil
        defer { sendingTestNotification = false }
        notificationPermission = await notifications.permission()
        if notificationPermission == .notDetermined {
            await beginPermissionRequest().value
            notificationPermission = await notifications.permission()
        }
        guard notificationPermission == .allowed else {
            showTestFeedback(notificationPermission == .denied
                ? L10n.string("Notifications are off in macOS. Open Notification Settings to allow them.")
                : L10n.string("Notification permission was not granted. Try again or open Notification Settings."), failed: true)
            return
        }
        do {
            try await notifications.sendTest(id: "native-agent-test-\(UUID().uuidString)")
            showTestFeedback(L10n.string("Test notification submitted to macOS. Check the banner or Notification Center."), failed: false)
        } catch {
            showTestFeedback(L10n.string("The test notification could not be submitted. Try again."), failed: true)
        }
    }

    private func showTestFeedback(_ text: String, failed: Bool) {
        testFeedbackTask?.cancel()
        testNotificationFeedback = text
        testNotificationFailed = failed
        testFeedbackTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(10))
            guard !Task.isCancelled else { return }
            self?.testNotificationFeedback = nil
        }
    }

    private func acknowledge(_ state: NativeMonitorState) {
        let next = MonitorNotificationCursor(session: state.session, removed: state.removed, failed: state.failed)
        guard next != cursor else { return }
        cursor = next
        if let data = try? JSONEncoder().encode(cursor) { defaults.set(data, forKey: Self.cursorKey) }
    }
    var title: String {
        if !enabled { return L10n.string("Monitoring is off") }
        guard let state, state.isFresh(at: Date()), state.enabled else { return L10n.string("Monitoring is not running or has not applied the setting yet") }
        switch state.status {
        case "clear": return L10n.string("Monitoring is active — no keys remain in the system agent at the last check")
        case "waiting": return L10n.string("Monitoring is waiting for Apple's SSH agent socket")
        case "disabled", "stopped": return L10n.string("Monitoring is not running or has not applied the setting yet")
        case "checking": return L10n.string("Checking the system agent")
        case "keys_present": return L10n.string("Keys remain in the system agent — removal will be retried")
        default: return L10n.string("Monitoring needs attention — removal or checking failed")
        }
    }
}

@MainActor
enum MonitorNotificationSettings {
    @discardableResult
    static func open(using open: (URL) -> Bool = { NSWorkspace.shared.open($0) }) -> Bool {
        // Current macOS pane, older macOS pane, then the app itself. This
        // navigates Settings only; no permission is changed by the button.
        for address in [
            "x-apple.systempreferences:com.apple.Notifications-Settings.extension",
            "x-apple.systempreferences:com.apple.preference.notifications"
        ] {
            if let url = URL(string: address), open(url) { return true }
        }
        return open(URL(fileURLWithPath: "/System/Applications/System Settings.app"))
    }
}

struct NativeAgentMonitorSection: View {
    @ObservedObject var model = NativeAgentMonitorModel.shared
    @State private var showingHelp = false
    @State private var settingsFailed = false
    var body: some View {
        Section {
            // One Form row: absent conditions cannot leave empty cells, and
            // Divider cannot become a tall standalone row.
            VStack(alignment: .leading, spacing: 12) {
                Toggle(L10n.string("Monitor key exposure through Apple's SSH agent"),
                       isOn: Binding(get: { model.enabled }, set: { model.setEnabled($0) }))
                Text(L10n.string("Removes detected keys from the system agent's memory and notifies you. A key may be used before the next check."))
                    .font(.callout).foregroundStyle(.secondary)
                Text(L10n.string("Private key files and Keychain passwords are kept."))
                    .font(.caption).foregroundStyle(.secondary)
                Label(model.title, systemImage: model.enabled ? "eye" : "eye.slash")
                    .font(.callout)
                if model.enabled && model.notificationPermission == .denied {
                    Text(L10n.string("macOS notifications are off. Monitoring and Security History remain active."))
                        .font(.callout).foregroundStyle(.orange)
                } else if model.enabled && model.notificationPermission == .notDetermined {
                    Text(L10n.string("macOS notification permission has not been granted."))
                        .font(.callout).foregroundStyle(.secondary)
                }
                HStack {
                    Button(L10n.string("Open Notification Settings")) {
                        settingsFailed = !MonitorNotificationSettings.open()
                    }
                    Button(L10n.string("Send Test Notification")) {
                        Task { await model.sendTestNotification() }
                    }
                    .disabled(model.sendingTestNotification)
                    .accessibilityLabel(L10n.string("Send Test Notification"))
                }
                if let feedback = model.testNotificationFeedback {
                    Text(feedback).font(.callout)
                        .foregroundStyle(model.testNotificationFailed ? Color.orange : Color.secondary)
                }
                if model.enabled, let error = model.notificationError {
                    Text(error).font(.callout).foregroundStyle(.orange)
                }
                if let error = model.error { Text(error).font(.callout).foregroundStyle(.red) }
                if settingsFailed {
                    Text(L10n.string("Open System Settings > Notifications > SSH Key Control."))
                        .font(.callout).foregroundStyle(.secondary)
                }
                HStack {
                    Button(L10n.string("Check Status")) { Task { await model.refresh() } }
                    Spacer()
                    Button(L10n.string("About Monitoring…")) { showingHelp = true }
                }
            }.padding(.vertical, 4)
        } header: { Text(L10n.string("System SSH agent")) }
        .task { await model.refresh() }
        .sheet(isPresented: $showingHelp) { NativeMonitorHelp() }
    }
}

private struct NativeMonitorHelp: View {
    @Environment(\.dismiss) private var dismiss
    @State private var settingsFailed = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.string("About System Agent Monitoring")).font(.title2).bold()
            Text(L10n.string("The background agent checks about once a second and removes detected keys from the system agent's memory. Results appear in Security History. A key may be used before detection."))
            Text(L10n.string("Private key files and Keychain passwords are kept. macOS notifications require permission; repeated events are grouped to avoid a flood."))
            Button(L10n.string("Open Notification Settings")) {
                settingsFailed = !MonitorNotificationSettings.open()
            }
            if settingsFailed { Text(L10n.string("Open System Settings > Notifications > SSH Key Control.")) }
            Text(L10n.string("The app does not change macOS protection."))
            HStack {
                Spacer()
                Button(L10n.string("Done")) { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
        .padding(24)
        .frame(width: 500)
    }
}
