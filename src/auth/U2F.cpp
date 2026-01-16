#include "U2F.hpp"
#include "../core/hyprlock.hpp"
#include "../helpers/Log.hpp"
#include "../config/ConfigManager.hpp"

#include <filesystem>
#include <chrono>
#include <cstring>
#include <fido.h>
#include <fido/credman.h>

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
    m_sPrompt      = m_sReadyMessage;

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
    return m_sState.waiting;
}

std::optional<std::string> CU2F::getLastFailText() {
    if (!m_sFailureReason.empty())
        return std::optional(m_sFailureReason);
    return std::nullopt;
}

std::optional<std::string> CU2F::getLastPrompt() {
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
    const auto        pollMs      = std::chrono::milliseconds(*POLLTIMEOUT);

    fido_dev_info_t* devList = fido_dev_info_new(64);
    if (!devList) {
        Debug::log(ERR, "u2f: failed to allocate device info");
        m_sFailureReason = "U2F initialization failed";
        m_sState.done    = true;
        return;
    }

    while (!m_sState.abort && !m_sState.done) {
        size_t nDevs = 0;
        int    r     = fido_dev_info_manifest(devList, 64, &nDevs);

        if (r != FIDO_OK) {
            Debug::log(WARN, "u2f: fido_dev_info_manifest failed: {}", fido_strerr(r));
            std::this_thread::sleep_for(pollMs);
            continue;
        }

        if (nDevs == 0) {
            if (m_sState.deviceFound) {
                // Device was removed
                m_sState.deviceFound = false;
                m_sState.waiting     = false;
                m_sPrompt            = m_sReadyMessage;
                Debug::log(LOG, "u2f: device removed");
                g_pHyprlock->enqueueForceUpdateTimers();
            }
            std::this_thread::sleep_for(pollMs);
            continue;
        }

        // Device found - only update UI once when first detected
        if (!m_sState.deviceFound) {
            m_sState.deviceFound = true;
            m_sState.waiting     = true;
            m_sPrompt            = m_sPresentMessage;
            Debug::log(LOG, "u2f: device detected, {} device(s) available", nDevs);
            g_pHyprlock->enqueueForceUpdateTimers();

            // Validate device is accessible (just once)
            const fido_dev_info_t* di   = fido_dev_info_ptr(devList, 0);
            const char*            path = fido_dev_info_path(di);
            tryAuthenticate(path);
        }

        // Device is present and waiting for PAM to complete authentication
        // Just keep polling to detect if device is removed
        std::this_thread::sleep_for(pollMs);
    }

    fido_dev_info_free(&devList, 64);
}

bool CU2F::tryAuthenticate(const char* devicePath) {
    // We only need to detect that the device is present
    // The actual PAM U2F module handles the cryptographic authentication
    // UI updates happen in pollForDevice() when device state changes
    // This function just validates the device is accessible

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

void CU2F::handleAuthResult(bool success, const std::string& error) {
    m_sState.waiting = false;
    m_sState.done    = true;

    if (success) {
        Debug::log(LOG, "u2f: authentication successful");
        g_pAuth->enqueueUnlock();
    } else {
        Debug::log(LOG, "u2f: authentication failed: {}", error);
        m_sFailureReason = error.empty() ? "U2F authentication failed" : error;
        g_pAuth->enqueueFail(m_sFailureReason, AUTH_IMPL_U2F);
    }

    g_pHyprlock->enqueueForceUpdateTimers();
}
