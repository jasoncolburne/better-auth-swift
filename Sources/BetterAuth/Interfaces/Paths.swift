import Foundation

public struct AuthenticatePaths: Sendable {
    public let start: String
    public let finish: String

    public init(start: String, finish: String) {
        self.start = start
        self.finish = finish
    }
}

public struct AccountPaths: Sendable {
    public let create: String

    public init(create: String) {
        self.create = create
    }
}

public struct RotatePaths: Sendable {
    public let authentication: String
    public let access: String
    public let link: String
    public let unlink: String
    public let recover: String

    public init(authentication: String, access: String, link: String, unlink: String, recover: String) {
        self.authentication = authentication
        self.access = access
        self.link = link
        self.unlink = unlink
        self.recover = recover
    }
}

public struct IAuthenticationPaths: Sendable {
    public let authenticate: AuthenticatePaths
    public let account: AccountPaths
    public let rotate: RotatePaths

    public init(authenticate: AuthenticatePaths, account: AccountPaths, rotate: RotatePaths) {
        self.authenticate = authenticate
        self.account = account
        self.rotate = rotate
    }
}
