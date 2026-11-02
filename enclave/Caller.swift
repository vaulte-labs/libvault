import Foundation
import Security

// Whether the process on the other end of the broker's socket is one of the vault's own apps. The
// kernel's audit token names that exact process, so one that connects and then turns into
// something else cannot borrow a signature it does not have.

@_cdecl("lv_peer_is_app")
public func lvPeerIsApp(_ token: UnsafePointer<UInt8>, _ tokenLength: Int, _ identifiers: UnsafePointer<CChar>) -> Bool {
    guard let team = ownTeam() else { return false }
    let allowed = String(cString: identifiers).split(separator: ",").map { "identifier \"\($0)\"" }.joined(separator: " or ")
    let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and (\(allowed))"
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else { return false }
    let attributes = [kSecGuestAttributeAudit: Data(bytes: token, count: tokenLength)] as CFDictionary
    var guest: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let guest else { return false }
    return SecCodeCheckValidity(guest, [], requirement) == errSecSuccess
}

/// Writes the team that signed this process into `out`, and returns its length, or 0 for none.
@_cdecl("lv_own_team")
public func lvOwnTeam(_ out: UnsafeMutablePointer<UInt8>, _ capacity: Int) -> Int {
    guard let team = ownTeam(), team.utf8.count <= capacity else { return 0 }
    let bytes = Array(team.utf8)
    out.update(from: bytes, count: bytes.count)
    return bytes.count
}

/// Writes the app group's container for `group` into `out`, creating it as the system does, and
/// returns the path's length, or 0 when this process may not have one.
@_cdecl("lv_group_container")
public func lvGroupContainer(_ group: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>, _ capacity: Int) -> Int {
    guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: String(cString: group)) else { return 0 }
    let bytes = Array(url.path.utf8)
    guard bytes.count <= capacity else { return 0 }
    out.update(from: bytes, count: bytes.count)
    return bytes.count
}

/// The team that signed this process. An unsigned or ad hoc build has none, so it trusts no one.
private func ownTeam() -> String? {
    var me: SecCode?
    var staticMe: SecStaticCode?
    var info: CFDictionary?
    guard SecCodeCopySelf([], &me) == errSecSuccess, let me,
          SecCodeCopyStaticCode(me, [], &staticMe) == errSecSuccess, let staticMe,
          SecCodeCopySigningInformation(staticMe, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess
    else { return nil }
    return (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
}
