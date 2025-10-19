import Foundation

public struct AccountPaths: Sendable {
    public let create: String
    public let recover: String
    public let delete: String

    public init(create: String, recover: String, delete: String) {
        self.create = create
        self.recover = recover
        self.delete = delete
    }
}

public struct SessionPaths: Sendable {
    public let request: String
    public let create: String
    public let refresh: String

    public init(request: String, create: String, refresh: String) {
        self.request = request
        self.create = create
        self.refresh = refresh
    }
}

public struct DevicePaths: Sendable {
    public let rotate: String
    public let link: String
    public let unlink: String

    public init(rotate: String, link: String, unlink: String) {
        self.rotate = rotate
        self.link = link
        self.unlink = unlink
    }
}

public struct RecoveryPaths: Sendable {
    public let change: String

    public init(change: String) {
        self.change = change
    }
}

public struct IAuthenticationPaths: Sendable {
    public let account: AccountPaths
    public let session: SessionPaths
    public let device: DevicePaths
    public let recovery: RecoveryPaths

    public init(account: AccountPaths, session: SessionPaths, device: DevicePaths, recovery: RecoveryPaths) {
        self.account = account
        self.session = session
        self.device = device
        self.recovery = recovery
    }
}
