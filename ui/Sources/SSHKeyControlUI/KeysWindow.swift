import AppKit
import SwiftUI

/// The key window: every key this Mac has in one list, with a switch that says
/// whether the agent holds it. Turning a switch on loads that key — which asks
/// for its passphrase, once — and turning it off takes it back out. There is no
/// Apply button because there is nothing to apply: the switch is the state.
struct KeysView: View {
    @ObservedObject var model: KeyringModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if model.rows.isEmpty {
                empty
            } else {
                List(model.rows) { row in
                    KeyRowView(row: row, model: model)
                }
                .listStyle(.inset)
            }
            Divider()
            footer
        }
        .frame(minWidth: 720, minHeight: 440)
        .task { await model.refresh() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(model.summary).font(.headline)
                if model.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button { Task { await model.refresh() } } label: { Image(systemName: "arrow.clockwise") }
                    .help(L10n.string("Refresh")).keyboardShortcut("r").disabled(model.busy)
            }
            Text(L10n.string("The agent keeps keys in memory only, and asks you before every signature. A key stays loaded until you turn it off, the agent restarts or this Mac does."))
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
    }

    private var empty: some View {
        VStack(spacing: 12) {
            Image(systemName: "key").font(.system(size: 32)).foregroundStyle(.secondary)
            Text(L10n.string("No keys found in ~/.ssh or your SSH config")).font(.title3).bold()
            Text(L10n.string("Add a key file to load it into the agent."))
                .foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let failure = model.failure {
                Text(failure).font(.callout).foregroundStyle(.red)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button(L10n.string("Add Key File…")) { addKeyFile() }
                Button(L10n.string("Unload All Keys…")) { unloadAll() }.disabled(!model.canUnload)
                Spacer()
            }.disabled(model.busy)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func addKeyFile() {
        let panel = NSOpenPanel()
        panel.message = L10n.string("Choose a private key file")
        panel.prompt = L10n.string("Add")
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await model.add(keyFile: url) }
    }

    private func unloadAll() {
        let confirm = NSAlert()
        confirm.messageText = L10n.string("Unload all keys from the agent?")
        confirm.informativeText = L10n.string("The keys are held in memory only, so SSH will ask for each passphrase again the next time it needs one. Saved passwords, temporary decisions and history are kept.")
        confirm.addButton(withTitle: L10n.string("Unload Keys"))
        confirm.addButton(withTitle: L10n.string("Cancel"))
        guard confirm.runModal() == .alertFirstButtonReturn else { return }
        Task { await model.unloadAll() }
    }
}

private struct KeyRowView: View {
    let row: KeyRow
    @ObservedObject var model: KeyringModel

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Toggle("", isOn: Binding(get: { row.loaded },
                                     set: { wanted in Task { await model.setLoaded(row, wanted) } }))
                .toggleStyle(.switch).labelsHidden()
                .disabled(model.busy || (row.loaded ? !row.canUnload : !row.canLoad))
                .help(row.loaded ? L10n.string("Take this key out of the agent")
                                 : L10n.string("Load this key into the agent"))
                .accessibilityLabel(L10n.format("%@ in the agent", row.name))
            VStack(alignment: .leading, spacing: 3) {
                Text(row.name).fontWeight(.medium)
                Text(row.detail).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
                Text(fingerprint).font(.caption).monospaced().foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                if row.asksAtEveryLogin {
                    Label(L10n.string("The passphrase is not saved, so this key asks for it at every login."),
                          systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 4) {
                Toggle(L10n.string("Load at login"),
                       isOn: Binding(get: { row.loadsAtLogin },
                                     set: { model.setLoadsAtLogin(row, $0) }))
                    .toggleStyle(.checkbox).disabled(!row.canLoad)
                    .help(L10n.string("Put this key into the agent when SSH Key Control starts"))
                HStack(spacing: 6) {
                    Text(passwordState).font(.caption).foregroundStyle(.secondary)
                    if row.remembered {
                        Button(L10n.string("Forget")) { model.forgetPassword(row) }
                            .buttonStyle(.link).font(.caption)
                    }
                }
                if row.addedByHand {
                    Button(L10n.string("Remove from list")) { Task { await model.removeFromList(row) } }
                        .buttonStyle(.link).font(.caption)
                }
            }
        }
        .padding(.vertical, 6)
    }

    // An older encrypted key gives up nothing until it is loaded, so until then
    // there is no fingerprint to show and saying so beats showing a blank.
    private var fingerprint: String {
        row.fingerprint.isEmpty ? L10n.string("Fingerprint known once the key is loaded") : row.fingerprint
    }

    private var passwordState: String {
        guard row.encrypted else { return L10n.string("No passphrase") }
        return row.remembered ? L10n.string("Password saved") : L10n.string("Password not saved")
    }
}

@MainActor
final class KeysWindowController: NSWindowController {
    init(model: KeyringModel) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 780, height: 480),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable],
                              backing: .buffered, defer: false)
        window.title = L10n.string("SSH Keys")
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: KeysView(model: model))
        window.setFrameAutosaveName("SSHKeyControlKeys")
        window.center()
        super.init(window: window)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func open() {
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}
