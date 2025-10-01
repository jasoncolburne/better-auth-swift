import Foundation

public struct AuthenticatePaths: Sendable {
    public let start: String
    public let finish: String

    public init(start: String, finish: String) {
        self.start = start
        self.finish = finish
    }
}

public struct RegisterPaths: Sendable {
    public let create: String
    public let link: String
    public let recover: String

    public init(create: String, link: String, recover: String) {
        self.create = create
        self.link = link
        self.recover = recover
    }
}

public struct RotatePaths: Sendable {
    public let authentication: String
    public let access: String

    public init(authentication: String, access: String) {
        self.authentication = authentication
        self.access = access
    }
}

public struct IAuthenticationPaths: Sendable {
    public let authenticate: AuthenticatePaths
    public let register: RegisterPaths
    public let rotate: RotatePaths

    public init(authenticate: AuthenticatePaths, register: RegisterPaths, rotate: RotatePaths) {
        self.authenticate = authenticate
        self.register = register
        self.rotate = rotate
    }
}
