#include "U2FCredentials.hpp"
#include "../helpers/Log.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <unistd.h>
#include <pwd.h>

// Base64url alphabet (RFC 4648)
static const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<uint8_t> CU2FCredentials::base64UrlDecode(const std::string& input) {
    std::vector<uint8_t> result;

    if (input.empty())
        return result;

    // Convert base64url to standard base64
    std::string base64 = input;
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');

    // Add padding if necessary
    while (base64.size() % 4 != 0) {
        base64 += '=';
    }

    // Decode
    int  val = 0;
    int  bits = 0;

    for (char c : base64) {
        if (c == '=')
            break;

        size_t pos = BASE64_CHARS.find(c);
        if (pos == std::string::npos) {
            Debug::log(WARN, "u2f credentials: invalid base64 character: {}", c);
            continue;
        }

        val = (val << 6) | static_cast<int>(pos);
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
        }
    }

    return result;
}

int CU2FCredentials::coseAlgorithmFromString(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "es256" || lower == "-7")
        return COSE_ES256;
    if (lower == "rs256" || lower == "-257")
        return COSE_RS256;

    // Default to ES256 if unrecognized
    Debug::log(WARN, "u2f credentials: unknown algorithm '{}', defaulting to ES256", str);
    return COSE_ES256;
}

std::optional<SU2FCredential> CU2FCredentials::parseCredentialEntry(const std::string& entry) {
    // Format: keyhandle,pubkey[,type[,options]]
    // Minimum: keyhandle,pubkey
    // pam_u2f uses comma-separated fields within each credential

    std::vector<std::string> fields;
    std::stringstream        ss(entry);
    std::string              field;

    while (std::getline(ss, field, ',')) {
        fields.push_back(field);
    }

    if (fields.size() < 2) {
        Debug::log(WARN, "u2f credentials: malformed credential entry (need at least keyhandle,pubkey): {}", entry);
        return std::nullopt;
    }

    SU2FCredential cred;

    // Field 0: keyhandle (credential ID)
    cred.credentialId = base64UrlDecode(fields[0]);
    if (cred.credentialId.empty()) {
        Debug::log(WARN, "u2f credentials: failed to decode keyhandle");
        return std::nullopt;
    }

    // Field 1: public key
    cred.publicKey = base64UrlDecode(fields[1]);
    if (cred.publicKey.empty()) {
        Debug::log(WARN, "u2f credentials: failed to decode public key");
        return std::nullopt;
    }

    // Field 2 (optional): algorithm type
    if (fields.size() > 2 && !fields[2].empty()) {
        cred.coseAlgorithm = coseAlgorithmFromString(fields[2]);
    }

    // Field 3 (optional): additional options
    if (fields.size() > 3) {
        cred.options = fields[3];
    }

    Debug::log(LOG, "u2f credentials: loaded credential with {} byte keyhandle, {} byte pubkey, algo={}",
               cred.credentialId.size(), cred.publicKey.size(), cred.coseAlgorithm);

    return cred;
}

bool CU2FCredentials::parseCredentialLine(const std::string& line, const std::string& targetUser) {
    // Format: username:cred1:cred2:cred3...
    // Each cred is: keyhandle,pubkey,type,options

    if (line.empty() || line[0] == '#')
        return false;

    // Find first colon (separates username from credentials)
    size_t colonPos = line.find(':');
    if (colonPos == std::string::npos)
        return false;

    std::string username = line.substr(0, colonPos);

    // Trim whitespace from username
    username.erase(0, username.find_first_not_of(" \t"));
    username.erase(username.find_last_not_of(" \t") + 1);

    if (username != targetUser)
        return false;

    // Parse credentials (colon-separated after username)
    std::string credsPart = line.substr(colonPos + 1);

    // Split by colon to get individual credentials
    std::stringstream ss(credsPart);
    std::string       credEntry;

    while (std::getline(ss, credEntry, ':')) {
        if (credEntry.empty())
            continue;

        auto cred = parseCredentialEntry(credEntry);
        if (cred.has_value()) {
            m_credentials.push_back(std::move(cred.value()));
        }
    }

    return !m_credentials.empty();
}

bool CU2FCredentials::loadFromFile(const std::string& path, const std::string& username) {
    m_credentials.clear();

    if (!std::filesystem::exists(path)) {
        Debug::log(WARN, "u2f credentials: file not found: {}", path);
        return false;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        Debug::log(ERR, "u2f credentials: failed to open file: {}", path);
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (parseCredentialLine(line, username)) {
            Debug::log(LOG, "u2f credentials: loaded {} credential(s) for user '{}'",
                       m_credentials.size(), username);
            return true;
        }
    }

    Debug::log(WARN, "u2f credentials: no credentials found for user '{}' in {}", username, path);
    return false;
}

bool CU2FCredentials::loadFromFile(const std::string& path) {
    auto* pw = getpwuid(getuid());
    if (!pw || !pw->pw_name) {
        Debug::log(ERR, "u2f credentials: failed to get current username");
        return false;
    }

    return loadFromFile(path, std::string(pw->pw_name));
}

bool CU2FCredentials::loadForCurrentUser() {
    auto* pw = getpwuid(getuid());
    if (!pw || !pw->pw_name) {
        Debug::log(ERR, "u2f credentials: failed to get current username");
        return false;
    }

    std::string username = pw->pw_name;

    // Try standard pam_u2f credential locations in order of preference
    std::vector<std::string> paths;

    // 1. User's Yubico directory (most common)
    if (pw->pw_dir) {
        paths.push_back(std::string(pw->pw_dir) + "/.config/Yubico/u2f_keys");
    }

    // 2. XDG config home
    if (const char* xdgConfig = getenv("XDG_CONFIG_HOME")) {
        paths.push_back(std::string(xdgConfig) + "/Yubico/u2f_keys");
    }

    // 3. System-wide location
    paths.push_back("/etc/u2f_keys");

    for (const auto& path : paths) {
        Debug::log(LOG, "u2f credentials: trying {}", path);
        if (loadFromFile(path, username)) {
            return true;
        }
    }

    Debug::log(WARN, "u2f credentials: no credential file found for user '{}'", username);
    return false;
}

const std::vector<SU2FCredential>& CU2FCredentials::getCredentials() const {
    return m_credentials;
}

bool CU2FCredentials::hasCredentials() const {
    return !m_credentials.empty();
}

size_t CU2FCredentials::count() const {
    return m_credentials.size();
}
