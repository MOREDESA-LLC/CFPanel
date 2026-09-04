import Foundation

@MainActor
final class CredentialPersistenceService {
    private let api: CloudflareAPI
    private let sessionStore: AuthSessionStore
    private let shellActions: AppShellActions

    init(
        api: CloudflareAPI,
        sessionStore: AuthSessionStore,
        shellActions: AppShellActions
    ) {
        self.api = api
        self.sessionStore = sessionStore
        self.shellActions = shellActions
    }

    func loadSavedCredentials(
        storageMode: CredentialStorageMode,
        fallbackTokenMode: AuthTokenMode,
        fallbackAccountID: String
    ) throws -> SavedCredentialLookup {
        let normalizedFallbackAccountID = fallbackAccountID.trimmingCharacters(in: .whitespacesAndNewlines)
        let loadedCredentials = try KeychainTokenStore.loadCredentials(
            storageMode: storageMode,
            fallbackMode: fallbackTokenMode,
            fallbackAccountID: normalizedFallbackAccountID
        )
        let legacyCredentials = loadedCredentials == nil
            ? try KeychainTokenStore.loadLegacyCredentials(
                fallbackMode: fallbackTokenMode,
                fallbackAccountID: normalizedFallbackAccountID
            )
            : nil

        return SavedCredentialLookup(
            credentials: loadedCredentials ?? legacyCredentials,
            didLoadLegacyCredentials: legacyCredentials != nil
        )
    }

    func migrateLegacyCredentials(
        _ credentials: StoredCloudflareCredentials,
        to storageMode: CredentialStorageMode
    ) throws {
        try KeychainTokenStore.save(credentials: credentials, storageMode: storageMode)
        try KeychainTokenStore.deleteLegacyCredentials()
        shellActions.logNotice("Migrated legacy Cloudflare credentials into \(storageMode.rawValue) keychain storage.")
    }

    func persistAuthenticatedSession(
        token: String,
        tokenMode: AuthTokenMode,
        accountID: String,
        authenticationMethod: AuthenticationMethod = .accountToken,
        oauthAccountName: String? = nil,
        oauthGrantedScopes: [String]? = nil
    ) {
        do {
            try KeychainTokenStore.save(
                credentials: StoredCloudflareCredentials(
                    token: token,
                    tokenMode: tokenMode,
                    accountID: accountID,
                    authenticationMethod: authenticationMethod,
                    oauthAccountName: oauthAccountName,
                    oauthGrantedScopes: oauthGrantedScopes
                ),
                storageMode: sessionStore.credentialStorageMode
            )
        } catch {
            shellActions.presentError(error)
        }
    }

    func persistCurrentCredentials(
        to storageMode: CredentialStorageMode,
        previousMode: CredentialStorageMode
    ) async throws {
        let resolvedToken = await api.currentToken()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        if sessionStore.isSignedIn, resolvedToken.isEmpty == false {
            let oauthPayload = sessionStore.authenticationMethod == .oauth
                ? try OAuthTokenStore.load(storageMode: previousMode)
                : nil

            try KeychainTokenStore.save(
                credentials: StoredCloudflareCredentials(
                    token: resolvedToken,
                    tokenMode: sessionStore.tokenMode,
                    accountID: sessionStore.accountIDInput.trimmingCharacters(in: .whitespacesAndNewlines),
                    authenticationMethod: sessionStore.authenticationMethod,
                    oauthAccountName: sessionStore.oauthAccountName.isEmpty ? nil : sessionStore.oauthAccountName,
                    oauthGrantedScopes: sessionStore.oauthGrantedScopes
                ),
                storageMode: storageMode
            )
            if let oauthPayload {
                try OAuthTokenStore.save(oauthPayload, storageMode: storageMode)
                try OAuthTokenStore.delete(storageMode: previousMode)
            }
            try KeychainTokenStore.deleteCredentials(storageMode: previousMode)
            try KeychainTokenStore.deleteLegacyCredentials()
            return
        }

        let modeCredentials = try KeychainTokenStore.loadCredentials(
            storageMode: previousMode,
            fallbackMode: sessionStore.tokenMode,
            fallbackAccountID: sessionStore.accountIDInput.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        let legacyCredentials = modeCredentials == nil
            ? try KeychainTokenStore.loadLegacyCredentials(
                fallbackMode: sessionStore.tokenMode,
                fallbackAccountID: sessionStore.accountIDInput.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            : nil
        let storedCredentials = modeCredentials ?? legacyCredentials

        guard let storedCredentials else {
            return
        }

        try KeychainTokenStore.save(credentials: storedCredentials, storageMode: storageMode)
        if storedCredentials.authenticationMethod == .oauth,
           let oauthPayload = try OAuthTokenStore.load(storageMode: previousMode) {
            try OAuthTokenStore.save(oauthPayload, storageMode: storageMode)
            try OAuthTokenStore.delete(storageMode: previousMode)
        }
        try KeychainTokenStore.deleteCredentials(storageMode: previousMode)
        try KeychainTokenStore.deleteLegacyCredentials()
    }

    func deletePersistedCredentials(storageMode: CredentialStorageMode) -> Error? {
        do {
            try KeychainTokenStore.deleteCredentials(storageMode: storageMode)
            try OAuthTokenStore.delete(storageMode: storageMode)
            try KeychainTokenStore.deleteLegacyCredentials()
            return nil
        } catch {
            return error
        }
    }

    func deleteAllCredentials() throws {
        try KeychainTokenStore.deleteAllCredentials()
        try OAuthTokenStore.deleteAll()
    }
}

struct SavedCredentialLookup {
    let credentials: StoredCloudflareCredentials?
    let didLoadLegacyCredentials: Bool
}
