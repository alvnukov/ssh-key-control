# Menu bar companion

The application is separate from the signing service. Its menu offers Security
History, Settings, About and Quit. launchd supervises both processes after
agent setup. Crashes restart with throttling; a successful exit from Quit stays
stopped until the next login or setup update. Closing a window or quitting this
app does not stop key protection. There is no new signing endpoint or approval
override.

The original mark combines a rectangular terminal outline and chevron with a
two-tooth key shaft. A template image lets macOS handle light/dark menu bars and
selection; the app icon uses the same geometry on a muted blue-green background.
The source is AppIdentity.swift. Iconset PNGs and AppIcon.icns are generated
during the build at exact 1x/2x pixel sizes.

Settings uses an AppKit toolbar with General and Advanced panes, fixed content
sizes, disabled minimize/zoom and Command–Comma. The title follows the active
pane and the last pane is restored. History is a separate resizable window;
its fingerprints are selectable and copyable. Command–H retains macOS Hide
semantics; history uses Command–Y.

Design references:
- [Apple: Settings](https://developer.apple.com/design/human-interface-guidelines/settings)
- [Apple: App icons](https://developer.apple.com/design/human-interface-guidelines/app-icons)
- [Apple: The menu bar](https://developer.apple.com/design/human-interface-guidelines/the-menu-bar)

The history is a diagnostic journal of gate decisions, not a shell-command log,
a record of successful logins, or tamper-evident evidence. It includes cached
decisions but excludes malformed requests rejected before the gate. It cannot
supply approvals on restart. Data and preferences have strict bounds and local
private permissions. Retention settings take effect at the next recorded event
on disk and at the next refresh in the view.

Validation uses Go race tests for observation, retention, concurrent writes,
restart persistence and unsafe paths; Swift tests for JSON compatibility,
bounds, settings persistence and native window conventions; and live inspection
of the generated app using macOS Accessibility and screen capture.
Login-item registration is only attempted when the user changes its switch.
