import AppKit

/// Original terminal-key mark, shared by the template image and app icon.
/// A rectangular bow with a terminal chevron avoids the familiar round key.
@MainActor
public enum AppIdentity {
    public static func menuImage() -> NSImage {
        let image = NSImage(size: NSSize(width: 20, height: 18), flipped: false) { _ in
            drawMark(in: NSRect(x: 1, y: 2, width: 18, height: 14), color: .black)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "SSH Key Control"
        return image
    }

    public static func applicationImage(size: CGFloat = 512) -> NSImage {
        NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            let tile = NSBezierPath(roundedRect: rect.insetBy(dx: size * 0.055, dy: size * 0.055),
                                    xRadius: size * 0.205, yRadius: size * 0.205)
            NSGradient(starting: NSColor(calibratedRed: 0.13, green: 0.30, blue: 0.37, alpha: 1),
                       ending: NSColor(calibratedRed: 0.06, green: 0.16, blue: 0.23, alpha: 1))!
                .draw(in: tile, angle: -75)
            drawMark(in: NSRect(x: size * 0.18, y: size * 0.25, width: size * 0.66, height: size * 0.50),
                     color: NSColor(calibratedWhite: 0.97, alpha: 1))
            return true
        }
    }

    private static func drawMark(in rect: NSRect, color: NSColor) {
        let scale = min(rect.width / 18, rect.height / 14)
        let transform = AffineTransform(translationByX: rect.minX, byY: rect.minY)
        func stroke(_ path: NSBezierPath, width: CGFloat) {
            var t = AffineTransform(scale: scale)
            path.transform(using: t)
            t = transform
            path.transform(using: t)
            path.lineWidth = width * scale
            path.lineCapStyle = .round
            path.lineJoinStyle = .round
            color.setStroke()
            path.stroke()
        }
        stroke(NSBezierPath(roundedRect: NSRect(x: 0.8, y: 2, width: 8.4, height: 10),
                            xRadius: 2, yRadius: 2), width: 1.5)
        let chevron = NSBezierPath()
        chevron.move(to: NSPoint(x: 3.2, y: 5))
        chevron.line(to: NSPoint(x: 5.4, y: 7))
        chevron.line(to: NSPoint(x: 3.2, y: 9))
        stroke(chevron, width: 1.35)
        let shaft = NSBezierPath()
        shaft.move(to: NSPoint(x: 9.2, y: 7))
        shaft.line(to: NSPoint(x: 17, y: 7))
        shaft.line(to: NSPoint(x: 17, y: 4))
        shaft.move(to: NSPoint(x: 13.5, y: 7))
        shaft.line(to: NSPoint(x: 13.5, y: 4))
        stroke(shaft, width: 1.7)
    }
}
