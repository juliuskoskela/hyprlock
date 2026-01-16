#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

// COSE algorithm identifiers
constexpr int COSE_ES256 = -7;   // ECDSA with SHA-256
constexpr int COSE_RS256 = -257; // RSASSA-PKCS1-v1_5 with SHA-256

struct SU2FCredential {
    std::vector<uint8_t> credentialId; // KeyHandle (base64url decoded)
    std::vector<uint8_t> publicKey;    // Public key bytes (base64url decoded)
    int                  coseAlgorithm = COSE_ES256;
    std::string          options;      // Additional options string
};

class CU2FCredentials {
  public:
    CU2FCredentials() = default;

    // Load credentials from file for the current user
    bool loadForCurrentUser();

    // Load credentials from a specific file path
    bool loadFromFile(const std::string& path);

    // Load credentials for a specific username from a file
    bool loadFromFile(const std::string& path, const std::string& username);

    // Get all loaded credentials
    const std::vector<SU2FCredential>& getCredentials() const;

    // Check if any credentials are loaded
    bool hasCredentials() const;

    // Get the number of loaded credentials
    size_t count() const;

  private:
    std::vector<SU2FCredential> m_credentials;

    // Parse a single credential entry (keyhandle,pubkey,type,options)
    std::optional<SU2FCredential> parseCredentialEntry(const std::string& entry);

    // Parse credential line for a specific user
    // Format: username:cred1:cred2:cred3...
    bool parseCredentialLine(const std::string& line, const std::string& targetUser);

    // COSE algorithm string to integer
    static int coseAlgorithmFromString(const std::string& str);

    // Base64url decode (handles both standard and URL-safe base64)
    static std::vector<uint8_t> base64UrlDecode(const std::string& input);
};
