import AppKit
import SSHKeyControlUI

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--render-assets" {
    let directory = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    let iconset = directory.appendingPathComponent("AppIcon.iconset", isDirectory: true)
    try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
    for size in [16, 32, 128, 256, 512] {
        for scale in [1, 2] {
            let pixels = CGFloat(size * scale)
            let image = AppIdentity.applicationImage(size: pixels)
            // Explicit pixel dimensions: NSImage otherwise inherits the display's
            // Retina scale and produces incorrectly sized iconset entries.
            let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(pixels), pixelsHigh: Int(pixels),
                bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
            NSGraphicsContext.saveGraphicsState()
            NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
            image.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
            NSGraphicsContext.restoreGraphicsState()
            let data = bitmap.representation(using: .png, properties: [:])!
            let suffix = scale == 2 ? "@2x" : ""
            try data.write(to: iconset.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
        }
    }
    let image = AppIdentity.menuImage()
    let cg = image.cgImage(forProposedRect: nil, context: nil, hints: nil)!
    try NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])!
        .write(to: directory.appendingPathComponent("MenuBarIcon.png"))
} else {
    let managed = CommandLine.arguments.contains("--managed")
    do {
        guard let instance = try ApplicationInstanceLock.acquire(wait: managed) else { exit(0) }
        let delegate = MenuBarApp(managed: managed)
        app.delegate = delegate
        withExtendedLifetime((delegate, instance)) { app.run() }
    } catch {
        FileHandle.standardError.write(Data("SSH Key Control could not secure its single-instance lock: \(error)\n".utf8))
        exit(1)
    }
}
