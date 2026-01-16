#include "U2F.hpp"
#include "../core/hyprlock.hpp"
#include "../helpers/Log.hpp"
#include "../config/ConfigManager.hpp"

#include <filesystem>
#include <chrono>
#include <cstring>
#include <fido.h>
#include <fido/credman.h>

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
    fido_dev_info_t* m_devList  = nullptr;
    size_t           m_maxDevs  = 0;
};

CU2F::CU2F() {
    static const auto READYMSG   = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:ready_message");
    m_sReadyMessage              = *READYMSG;
    static const auto PRESENTMSG = g_pConfigManager->getValue<Hyprlang::STRING>("auth:u2f:present_message");
    m_sPresentMessage            = *PRESENTMSG;
}

CU2F::~CU2F() {
    terminate();
}

void CU2F::init() {
    m_sState.abort = false;
    m_sState.done  = false;

    {
        std::lock_guard<std::mutex> lock(m_stringMutex);
        m_sPrompt = m_sReadyMessage;
    }

    // Start polling for U2F device in background thread
    m_pollThread = std::thread(&CU2F::pollForDevice, this);

    Debug::log(LOG, "u2f: initialized, waiting for device");
    g_pHyprlock->enqueueForceUpdateTimers();
}

void CU2F::handleInput(const std::string& input) {
    // U2F doesn't use keyboard input - it's touch-based
    // But receiving input means user pressed Enter, which could trigger PAM
    // We don't interfere with that
}

bool CU2F::checkWaiting() {
    // U2F should never block keyboard input.
    // This module only handles device presence detection for UI updates.
    // Actual U2F authentication is handled by PAM's pam_u2f module.
    // Returning true here would block password input, causing a deadlock
    // when both native U2F and PAM U2F are enabled.
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

void CU2F::pollForDevice() {
    static const auto POLLTIMEOUT = g_pConfigManager->getValue<Hyprlang::INT>("auth:u2f:poll_interval");

    // Validate poll interval to prevent CPU spin or negative values
    const int pollInterval = std::max(10, static_cast<int>(*POLLTIMEOUT));
    const auto pollMs = std::chrono::milliseconds(pollInterval);

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

        // Device found - only update UI once when first detected
        if (!m_sState.deviceFound) {
            m_sState.deviceFound = true;
            {
                std::lock_guard<std::mutex> lock(m_stringMutex);
                m_sPrompt = m_sPresentMessage;
            }
            Debug::log(LOG, "u2f: device detected, {} device(s) available", nDevs);
            g_pHyprlock->enqueueForceUpdateTimers();

            // Validate device is accessible (just once)
            const fido_dev_info_t* di = fido_dev_info_ptr(devList.get(), 0);
            if (di) {
                const char* path = fido_dev_info_path(di);
                if (path)
                    tryAuthenticate(path);
                else
                    Debug::log(WARN, "u2f: device path is null");
            } else {
                Debug::log(WARN, "u2f: device info pointer is null");
            }
        }

        // Device is present and waiting for PAM to complete authentication
        // Just keep polling to detect if device is removed
        std::this_thread::sleep_for(pollMs);
    }
}

bool CU2F::tryAuthenticate(const char* devicePath) {
    // We only need to detect that the device is present
    // The actual PAM U2F module handles the cryptographic authentication
    // UI updates happen in pollForDevice() when device state changes
    // This function just validates the device is accessible

    if (!devicePath) {
        Debug::log(WARN, "u2f: tryAuthenticate called with null path");
        return false;
    }

    fido_dev_t* dev = fido_dev_new();
    if (!dev) {
        Debug::log(ERR, "u2f: failed to allocate device");
        return false;
    }

    int r = fido_dev_open(dev, devicePath);
    if (r != FIDO_OK) {
        Debug::log(WARN, "u2f: failed to open device {}: {}", devicePath, fido_strerr(r));
        fido_dev_free(&dev);
        return false;
    }

    fido_dev_close(dev);
    fido_dev_free(&dev);

    // Return false - PAM handles the actual unlock via pam_u2f
    return false;
}
