import SwiftUI

struct SystemAgentSettingsSection: View {
    @ObservedObject var model: NativeAgentMonitorModel
    var body: some View { NativeAgentMonitorSection(model: model) }
}
