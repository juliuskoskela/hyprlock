#include "U2F.hpp"
#include "../core/hyprlock.hpp"
#include "../helpers/Log.hpp"
#include "../config/ConfigManager.hpp"

#include <filesystem>
#include <chrono>
#include <cstring>
#include <fido.h>
#include <fido/es256.h>

// For secure random generation
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

// RAII wrapper for fido_dev_info_t to prevent resource leaks
class FidoDevInfoGuard {
  public:
    FidoDevInfoGuard(size_t maxDevs) : m_maxDevs(maxDevs) {
        m_devList = fido_dev_info_new(maxDevs);
    }
    ~FidoDevInfoGuard() {
        if (m_devList)
            fido_dev_info_free(&m_devList, m_maxDevs);
    }

    FidoDevInfoGuard(const FidoDevInfoGuard&)            = delete;
    FidoDevInfoGuard& operator=(const FidoDevInfoGuard&) = delete;

    fido_dev_info_t* get() const {
        return m_devList;
    }
    explicit operator bool() const {
        return m_devList != nullptr;
    }

  private:
    fido_dev_info_t* m_devList = nullptr;
    size_t           m_maxDevs = 0;
};

// RAII wrapper for fido_dev_t
class FidoDevGuard {
  public:
    FidoDevGuard() {
        m_dev = fido_dev_new();
    }
    ~FidoDevGuard() {
        if (m_dev) {
            fido_dev_close(m_dev);
            fido_dev_free(&m_dev);
        }
    }

    FidoDevGuard(const FidoDevGuard&)            = delete;
    FidoDevGuard& operator=(const FidoDevGuard&) = delete;

    fido_dev_t* get() const {
        return m_dev;
    }
    explicit operator bool() const {
        return m_dev != nullptr;
    }

    bool open(const char* path) {
        if (!m_dev || !path)
            return false;
        int r = fido_dev_open(m_dev, path);
        return r == FIDO_OK;
    }

  private:
    fido_dev_t* m_dev = nullptr;
};

// RAII wrapper for fido_assert_t
class FidoAssertGuard {
  public:
    FidoAssertGuard() {
        m_assert = fido_assert_new();
    }
    ~FidoAssertGuard() {
        if (m_assert)
            fido_assert_free(&m_assert);
    }

    FidoAssertGuard(const FidoAssertGuard&)            = delete;
    FidoAssertGuard& operator=(const FidoAssertGuard&) = delete;

    fido_assert_t* get() const {
        return m_assert;
    }
    explicit operator bool() const {
        return m_assert != nullptr;
    }

  private:
    fido_assert_t* m_assert = nullptr;
};

// RAII guard to ensure authenticating state is always reset
class AuthenticatingGuard {
  public:
    AuthenticatingGuard(std::atomic<bool>& flag) : m_flag(flag) {
        m_flag = true;
    }
    ~AuthenticatingGuard() {
        m_flag = false;
    }

    AuthenticatingGuard(const AuthenticatingGuard&)            = delete;
    AuthenticatingGuard& operator=(const AuthenticatingGuard&) = delete;

  private:
    std::atomic<bool>& m_flag;
};

CU2F::CU2F() {
    // Load UI messages
    static const auto READYMSG = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:ready_message");
    m_sReadyMessage            = *READYMSG;

    static const auto PRESENTMSG = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:present_message");
    m_sPresentMessage            = *PRESENTMSG;

    static const auto VERIFYINGMSG = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:verifying_message");
    m_sVerifyingMessage            = *VERIFYINGMSG;

    // Load FIDO2 config
    static const auto RPID = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:rp_id");
    m_sRelyingPartyId      = *RPID;

    static const auto AUTHFILE = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:authfile");
    m_sAuthFile                = *AUTHFILE;

    static const auto TIMEOUT = g_pConfigManager->getValue<Hyprlang::INT>("auth:u2f:timeout");
    m_iTimeout                = static_cast<int>(*TIMEOUT);

    Debug::log(LOG, "u2f: configured with rp_id='{}', authfile='{}', timeout={}ms",
               m_sRelyingPartyId, m_sAuthFile.empty() ? "(auto)" : m_sAuthFile, m_iTimeout);
}

CU2F::~CU2F() {
    terminate();
}

void CU2F::init() {
    m_sState.abort        = false;
    m_sState.done         = false;
    m_sState.deviceFound  = false;
    m_sState.authenticating = false;

    // Load credentials
    bool credentialsLoaded = false;
    if (!m_sAuthFile.empty()) {
        credentialsLoaded = m_credentials.loadFromFile(m_sAuthFile);
    } else {
        credentialsLoaded = m_credentials.loadForCurrentUser();
    }

    if (!credentialsLoaded || !m_credentials.hasCredentials()) {
        Debug::log(WARN, "u2f: no credentials found, U2F authentication will not work");
        {
            std::lock_guard<std::mutex> lock(m_stringMutex);
            m_sFailureReason = "No U2F credentials configured";
            m_sPrompt        = "";
        }
        m_sState.done = true;
        return;
    }

    Debug::log(LOG, "u2f: loaded {} credential(s)", m_credentials.count());

    {
        std::lock_guard<std::mutex> lock(m_stringMutex);
        m_sPrompt = m_sReadyMessage;
    }

    // Start polling for U2F device in background thread
    try {
        m_pollThread = std::thread(&CU2F::pollForDevice, this);
    } catch (const std::system_error& e) {
        Debug::log(ERR, "u2f: failed to create polling thread: {}", e.what());
        m_sState.done = true;
        {
            std::lock_guard<std::mutex> lock(m_stringMutex);
            m_sFailureReason = "Failed to initialize U2F";
        }
        return;
    }

    if (!m_pollThread.joinable()) {
        Debug::log(ERR, "u2f: polling thread not joinable after creation");
        m_sState.done = true;
        return;
    }

    Debug::log(LOG, "u2f: initialized, waiting for device");
    g_pHyprlock->enqueueForceUpdateTimers();
}

void CU2F::handleInput(const std::string& input) {
    // U2F doesn't use keyboard input - it's touch-based
    // This allows password input to pass through to PAM
}

bool CU2F::checkWaiting() {
    // U2F should never block keyboard input.
    // Password authentication via PAM should always be available as fallback.
    return false;
}

std::optional<std::string> CU2F::getLastFailText() {
    std::lock_guard<std::mutex> lock(m_stringMutex);
    if (!m_sFailureReason.empty())
        return std::optional(m_sFailureReason);
    return std::nullopt;
}

std::optional<std::string> CU2F::getLastPrompt() {
    std::lock_guard<std::mutex> lock(m_stringMutex);
    if (!m_sPrompt.empty())
        return std::optional(m_sPrompt);
    return std::nullopt;
}

void CU2F::terminate() {
    m_sState.abort = true;
    if (m_pollThread.joinable())
        m_pollThread.join();
}

bool CU2F::generateChallenge(unsigned char* buffer, size_t length) {
    if (!buffer || length == 0)
        return false;

    // Read from /dev/urandom for cryptographically secure random bytes
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        Debug::log(ERR, "u2f: failed to open /dev/urandom: {}", strerror(errno));
        return false;
    }

    // Loop to handle partial reads (can happen on interrupt)
    size_t totalRead = 0;
    while (totalRead < length) {
        ssize_t bytesRead = read(fd, buffer + totalRead, length - totalRead);
        if (bytesRead < 0) {
            if (errno == EINTR)
                continue;  // Interrupted, retry
            Debug::log(ERR, "u2f: read from /dev/urandom failed: {}", strerror(errno));
            close(fd);
            return false;
        }
        if (bytesRead == 0) {
            // EOF on /dev/urandom should never happen
            Debug::log(ERR, "u2f: unexpected EOF on /dev/urandom");
            close(fd);
            return false;
        }
        totalRead += static_cast<size_t>(bytesRead);
    }

    if (close(fd) < 0) {
        Debug::log(WARN, "u2f: close() on /dev/urandom failed: {}", strerror(errno));
        // Non-fatal - we got our random bytes
    }

    return true;
}

void CU2F::pollForDevice() {
    static const auto POLLTIMEOUT = g_pConfigManager->getValue<Hyprlang::INT>("auth:u2f:poll_interval");

    // Validate poll interval to prevent CPU spin or negative values
    const int  pollInterval = std::max(10, static_cast<int>(*POLLTIMEOUT));
    const auto pollMs       = std::chrono::milliseconds(pollInterval);

    constexpr size_t MAX_DEVICES = 64;
    FidoDevInfoGuard devList(MAX_DEVICES);

    if (!devList) {
        Debug::log(ERR, "u2f: failed to allocate device info");
        {
            std::lock_guard<std::mutex> lock(m_stringMutex);
            m_sFailureReason = "U2F initialization failed";
        }
        m_sState.done = true;
        return;
    }

    while (!m_sState.abort && !m_sState.done) {
        // Skip polling while authentication is in progress
        if (m_sState.authenticating) {
            std::this_thread::sleep_for(pollMs);
            continue;
        }

        size_t nDevs = 0;
        int    r     = fido_dev_info_manifest(devList.get(), MAX_DEVICES, &nDevs);

        if (r != FIDO_OK) {
            Debug::log(WARN, "u2f: fido_dev_info_manifest failed: {}", fido_strerr(r));
            std::this_thread::sleep_for(pollMs);
            continue;
        }

        if (nDevs == 0) {
            if (m_sState.deviceFound) {
                // Device was removed
                m_sState.deviceFound = false;
                {
                    std::lock_guard<std::mutex> lock(m_stringMutex);
                    m_sPrompt = m_sReadyMessage;
                }
                Debug::log(LOG, "u2f: device removed");
                g_pHyprlock->enqueueForceUpdateTimers();
            }
            std::this_thread::sleep_for(pollMs);
            continue;
        }

        // Device found
        if (!m_sState.deviceFound) {
            m_sState.deviceFound = true;
            {
                std::lock_guard<std::mutex> lock(m_stringMutex);
                m_sPrompt = m_sPresentMessage;
            }
            Debug::log(LOG, "u2f: device detected, {} device(s) available", nDevs);
            g_pHyprlock->enqueueForceUpdateTimers();

            // Get device path and attempt authentication
            const fido_dev_info_t* di = fido_dev_info_ptr(devList.get(), 0);
            if (di) {
                const char* path = fido_dev_info_path(di);
                if (path) {
                    // Perform FIDO2 assertion
                    if (performAssertion(path)) {
                        // Success! Unlock handled inside performAssertion
                        m_sState.done = true;
                        return;
                    }
                    // Assertion failed, continue polling for retry
                } else {
                    Debug::log(WARN, "u2f: device path is null");
                }
            } else {
                Debug::log(WARN, "u2f: device info pointer is null");
            }
        }

        std::this_thread::sleep_for(pollMs);
    }
}

bool CU2F::performAssertion(const char* devicePath) {
    if (!devicePath) {
        Debug::log(ERR, "u2f: performAssertion called with null path");
        return false;
    }

    // RAII guard ensures authenticating is always reset on exit
    AuthenticatingGuard authGuard(m_sState.authenticating);

    // Update UI to show we're verifying
    {
        std::lock_guard<std::mutex> lock(m_stringMutex);
        m_sPrompt = m_sVerifyingMessage;
    }
    g_pHyprlock->enqueueForceUpdateTimers();

    Debug::log(LOG, "u2f: starting assertion with device {}", devicePath);

    // Generate random challenge (32 bytes = 256 bits)
    constexpr size_t CHALLENGE_SIZE = 32;
    unsigned char    challenge[CHALLENGE_SIZE];
    if (!generateChallenge(challenge, CHALLENGE_SIZE)) {
        Debug::log(ERR, "u2f: failed to generate challenge");
        {
            std::lock_guard<std::mutex> lock(m_stringMutex);
            m_sFailureReason = "Failed to generate challenge";
            m_sPrompt        = m_sPresentMessage;
        }
        return false;
    }

    // Create assertion object
    FidoAssertGuard assertion;
    if (!assertion) {
        Debug::log(ERR, "u2f: failed to allocate assertion");
        return false;
    }

    // Set relying party ID
    int r = fido_assert_set_rp(assertion.get(), m_sRelyingPartyId.c_str());
    if (r != FIDO_OK) {
        Debug::log(ERR, "u2f: fido_assert_set_rp failed: {}", fido_strerr(r));
        return false;
    }

    // Set the challenge (client data hash)
    r = fido_assert_set_clientdata_hash(assertion.get(), challenge, CHALLENGE_SIZE);
    if (r != FIDO_OK) {
        Debug::log(ERR, "u2f: fido_assert_set_clientdata_hash failed: {}", fido_strerr(r));
        return false;
    }

    // Require user presence (touch)
    r = fido_assert_set_up(assertion.get(), FIDO_OPT_TRUE);
    if (r != FIDO_OK) {
        Debug::log(ERR, "u2f: fido_assert_set_up failed: {}", fido_strerr(r));
        return false;
    }

    // Add all allowed credentials
    for (const auto& cred : m_credentials.getCredentials()) {
        r = fido_assert_allow_cred(assertion.get(), cred.credentialId.data(), cred.credentialId.size());
        if (r != FIDO_OK) {
            Debug::log(WARN, "u2f: fido_assert_allow_cred failed: {}", fido_strerr(r));
        }
    }

    // Open device
    FidoDevGuard dev;
    if (!dev) {
        Debug::log(ERR, "u2f: failed to allocate device");
        return false;
    }

    if (!dev.open(devicePath)) {
        Debug::log(ERR, "u2f: failed to open device {}", devicePath);
        {
            std::lock_guard<std::mutex> lock(m_stringMutex);
            m_sFailureReason = "Failed to open security key";
            m_sPrompt        = m_sPresentMessage;
        }
        return false;
    }

    // Set timeout (log but don't fail on error - it's non-fatal)
    r = fido_dev_set_timeout(dev.get(), m_iTimeout);
    if (r != FIDO_OK) {
        Debug::log(WARN, "u2f: fido_dev_set_timeout failed: {} (continuing anyway)", fido_strerr(r));
    }

    Debug::log(LOG, "u2f: requesting assertion (waiting for touch)...");

    // Request assertion - THIS BLOCKS waiting for user touch
    r = fido_dev_get_assert(dev.get(), assertion.get(), nullptr);  // nullptr = no PIN

    if (m_sState.abort) {
        // Abort was requested during the blocking call
        return false;
    }

    if (r != FIDO_OK) {
        Debug::log(WARN, "u2f: fido_dev_get_assert failed: {}", fido_strerr(r));
        m_sState.deviceFound = false;  // Reset to allow retry

        std::string errorMsg;
        switch (r) {
            case FIDO_ERR_ACTION_TIMEOUT: errorMsg = "Touch timeout"; break;
            case FIDO_ERR_PIN_REQUIRED: errorMsg = "PIN required (not supported)"; break;
            case FIDO_ERR_NO_CREDENTIALS: errorMsg = "No matching credentials"; break;
            case FIDO_ERR_USER_PRESENCE_REQUIRED: errorMsg = "Touch required"; break;
            default: errorMsg = "Authentication failed"; break;
        }

        {
            std::lock_guard<std::mutex> lock(m_stringMutex);
            m_sFailureReason = errorMsg;
            m_sPrompt        = m_sReadyMessage;
        }
        g_pHyprlock->enqueueForceUpdateTimers();
        return false;
    }

    Debug::log(LOG, "u2f: assertion received, verifying signature...");

    // Verify the signature against our stored credentials
    for (const auto& cred : m_credentials.getCredentials()) {
        if (verifyAssertionSignature(assertion.get(), cred)) {
            Debug::log(LOG, "u2f: signature verified successfully!");
            // SUCCESS - trigger unlock (AuthenticatingGuard resets state on return)
            g_pAuth->enqueueUnlock();
            return true;
        }
    }

    Debug::log(WARN, "u2f: signature verification failed for all credentials");
    m_sState.deviceFound = false;  // Reset to allow retry

    {
        std::lock_guard<std::mutex> lock(m_stringMutex);
        m_sFailureReason = "Signature verification failed";
        m_sPrompt        = m_sReadyMessage;
    }
    g_pHyprlock->enqueueForceUpdateTimers();
    return false;
}

bool CU2F::verifyAssertionSignature(fido_assert_t* assertion, const SU2FCredential& cred) {
    if (!assertion)
        return false;

    // Currently only ES256 (COSE algorithm -7) is supported
    if (cred.coseAlgorithm != COSE_ES256) {
        Debug::log(WARN, "u2f: unsupported algorithm {}, only ES256 (-7) is supported", cred.coseAlgorithm);
        return false;
    }

    // Create ES256 public key
    es256_pk_t* pk = es256_pk_new();
    if (!pk) {
        Debug::log(ERR, "u2f: failed to allocate ES256 public key");
        return false;
    }

    // Load public key from stored bytes
    // pam_u2f stores the public key in COSE format or raw uncompressed format
    int r = es256_pk_from_ptr(pk, cred.publicKey.data(), cred.publicKey.size());
    if (r != FIDO_OK) {
        Debug::log(WARN, "u2f: failed to load ES256 public key: {} (size={})",
                   fido_strerr(r), cred.publicKey.size());
        es256_pk_free(&pk);
        return false;
    }

    // Verify the assertion signature
    // Index 0 = first (and typically only) assertion
    r = fido_assert_verify(assertion, 0, COSE_ES256, pk);

    es256_pk_free(&pk);

    if (r == FIDO_OK) {
        Debug::log(LOG, "u2f: ES256 signature verified");
        return true;
    }

    Debug::log(WARN, "u2f: signature verification failed: {}", fido_strerr(r));
    return false;
}
