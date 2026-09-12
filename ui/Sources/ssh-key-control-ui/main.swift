// ssh-key-control-ui shows the dialogs and reads the keychain for ssh-key-control.
// It is started by ssh-key-control, speaks JSON lines on stdin/stdout and exits
// when its input ends.
import AppKit
import SSHKeyControlUI

let app = NSApplication.shared
app.setActivationPolicy(.accessory)

let dispatcher = Dispatcher(dialogs: AppKitDialogs(), store: Keychain())
let server = LineServer(
    handler: { dispatcher.handle($0) },
    finished: { app.terminate(nil) }
)
server.start()
app.run()
