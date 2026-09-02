import Foundation
import Security

enum OAuthTokenStore {
    private static let localService = "org.zhaohe.CFPanel.cloudflare-oauth.local"
    private static let syncedService = "org.zhaohe.CFPanel.cloudflare-oauth.synced"
    private static let account = "primary"

    static func save(_ payload: OAuthTokenPayload, storageMode: CredentialStorageMode) throws {
        let data = try JSONEncoder().encode(payload)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service(for: storageMode),
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizableValue(for: storageMode),
            kSecAttrAccessible: accessibleValue(for: storageMode),
            kSecValueData: data
        ]

        let addStatus = SecItemAdd(query as CFDictionary, nil)
        switch addStatus {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            let updateQuery: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service(for: storageMode),
                kSecAttrAccount: account,
                kSecAttrSynchronizable: synchronizableValue(for: storageMode)
            ]
            let attributes: [CFString: Any] = [
                kSecAttrAccessible: accessibleValue(for: storageMode),
                kSecValueData: data
            ]
            let updateStatus = SecItemUpdate(updateQuery as CFDictionary, attributes as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw KeychainTokenStoreError.unhandled(updateStatus)
            }
        default:
            throw KeychainTokenStoreError.unhandled(addStatus)
        }
    }

    static func load(storageMode: CredentialStorageMode) throws -> OAuthTokenPayload? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service(for: storageMode),
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizableValue(for: storageMode),
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw KeychainTokenStoreError.invalidPayload
            }
            return try JSONDecoder().decode(OAuthTokenPayload.self, from: data)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainTokenStoreError.unhandled(status)
        }
    }

    static func delete(storageMode: CredentialStorageMode) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service(for: storageMode),
            kSecAttrAccount: account,
            kSecAttrSynchronizable: synchronizableValue(for: storageMode)
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainTokenStoreError.unhandled(status)
        }
    }

    static func deleteAll() throws {
        try delete(storageMode: .local)
        try delete(storageMode: .synced)
    }

    private static func service(for storageMode: CredentialStorageMode) -> String {
        switch storageMode {
        case .local:
            return localService
        case .synced:
            return syncedService
        }
    }

    private static func synchronizableValue(for storageMode: CredentialStorageMode) -> Any {
        switch storageMode {
        case .local:
            return kCFBooleanFalse as Any
        case .synced:
            return kCFBooleanTrue as Any
        }
    }

    private static func accessibleValue(for storageMode: CredentialStorageMode) -> CFString {
        switch storageMode {
        case .local:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .synced:
            return kSecAttrAccessibleWhenUnlocked
        }
    }
}
