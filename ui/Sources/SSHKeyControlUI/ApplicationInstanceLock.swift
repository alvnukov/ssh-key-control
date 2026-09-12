import Darwin
import Foundation

public final class ApplicationInstanceLock: @unchecked Sendable {
    private let descriptor: Int32

    public static var defaultURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/SSH Key Control", isDirectory: true)
            .appendingPathComponent("menu-bar.lock")
    }

    public static func acquire(at url: URL = defaultURL, wait: Bool) throws -> ApplicationInstanceLock? {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let descriptor = Darwin.open(url.path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw posixError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              info.st_uid == getuid(),
              info.st_mode & S_IFMT == S_IFREG else {
            Darwin.close(descriptor)
            throw CocoaError(.fileReadNoPermission)
        }
        _ = fchmod(descriptor, S_IRUSR | S_IWUSR)
        let operation = LOCK_EX | (wait ? 0 : LOCK_NB)
        guard flock(descriptor, operation) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            if !wait && (code == EWOULDBLOCK || code == EAGAIN) { return nil }
            throw posixError(code)
        }
        return ApplicationInstanceLock(descriptor: descriptor)
    }

    private init(descriptor: Int32) { self.descriptor = descriptor }

    deinit { Darwin.close(descriptor) }
}

private func posixError(_ code: Int32 = errno) -> Error {
    POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
}
