#include "Pam.hpp"
#include "../core/hyprlock.hpp"
#include "../helpers/Log.hpp"
#include "../config/ConfigManager.hpp"

#include <filesystem>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>
#if __has_include(<security/pam_misc.h>)
#include <security/pam_misc.h>
#endif

#include <cstring>
#include <thread>

// Helper to clean up partially-filled PAM response array
static void cleanupPamReply(struct pam_response* reply, int count) {
    if (!reply)
        return;
    for (int i = 0; i < count; ++i) {
        if (reply[i].resp) {
            free(reply[i].resp);
            reply[i].resp = nullptr;
        }
    }
    free(reply);
}

int conv(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
    // Validate inputs
    if (!msg || !resp || !appdata_ptr || num_msg <= 0 || num_msg > 256) {
        Debug::log(ERR, "PAM: invalid conversation parameters");
        return PAM_CONV_ERR;
    }

    const auto           CONVERSATIONSTATE = (CPam::SPamConversationState*)appdata_ptr;
    struct pam_response* pamReply          = (struct pam_response*)calloc(num_msg, sizeof(struct pam_response));

    if (!pamReply) {
        Debug::log(ERR, "PAM: failed to allocate response buffer");
        return PAM_BUF_ERR;
    }

    bool initialPrompt    = true;
    int  allocatedResponses = 0;  // Track how many responses we've allocated for cleanup

    for (int i = 0; i < num_msg; ++i) {
        // Validate message pointer
        if (!msg[i]) {
            Debug::log(WARN, "PAM: null message at index {}", i);
            continue;
        }

        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON: {
                // Validate message text
                const char* msgText = msg[i]->msg;
                if (!msgText)
                    msgText = "";

                const auto PROMPT        = std::string(msgText);
                const auto PROMPTCHANGED = PROMPT != CONVERSATIONSTATE->prompt;
                Debug::log(LOG, "PAM_PROMPT: {}", PROMPT);

                if (PROMPTCHANGED)
                    g_pHyprlock->enqueueForceUpdateTimers();

                // Some pam configurations ask for the password twice for whatever reason (Fedora su for example)
                // When the prompt is the same as the last one, I guess our answer can be the same.
                if (!initialPrompt && PROMPTCHANGED) {
                    CONVERSATIONSTATE->prompt = PROMPT;
                    CONVERSATIONSTATE->waitForInput();
                }

                // Needed for unlocks via SIGUSR1
                if (g_pHyprlock->isUnlocked()) {
                    cleanupPamReply(pamReply, allocatedResponses);
                    return PAM_CONV_ERR;
                }

                char* respStr = strdup(CONVERSATIONSTATE->input.c_str());
                if (!respStr) {
                    Debug::log(ERR, "PAM: strdup failed - out of memory");
                    cleanupPamReply(pamReply, allocatedResponses);
                    return PAM_BUF_ERR;
                }
                pamReply[i].resp = respStr;
                allocatedResponses = i + 1;  // Track for cleanup
                initialPrompt    = false;
            } break;
            case PAM_ERROR_MSG: {
                const char* msgText = msg[i]->msg ? msg[i]->msg : "(null)";
                Debug::log(ERR, "PAM: {}", msgText);
            } break;
            case PAM_TEXT_INFO: {
                const char* msgText = msg[i]->msg;
                if (!msgText)
                    break;
                Debug::log(LOG, "PAM: {}", msgText);
                // Targets this log from pam_faillock
                if (const auto MSG = std::string(msgText); MSG.contains("left to unlock")) {
                    CONVERSATIONSTATE->failText        = MSG;
                    CONVERSATIONSTATE->failTextFromPam = true;
                }
            } break;
        }
    }

    *resp = pamReply;
    return PAM_SUCCESS;
}

CPam::CPam() {
    static const auto PAMMODULE = g_pConfigManager->getValue<Hyprlang::STRING>("auth:pam:module");
    m_sPamModule                = *PAMMODULE;

    if (!std::filesystem::exists(std::filesystem::path("/etc/pam.d/") / m_sPamModule)) {
        Debug::log(ERR, R"(Pam module "/etc/pam.d/{}" does not exist! Falling back to "/etc/pam.d/su")", m_sPamModule);
        m_sPamModule = "su";
    }

    m_sConversationState.waitForInput = [this]() { this->waitForInput(); };
}

CPam::~CPam() {
    terminate();
}

void CPam::init() {
    m_thread = std::thread([this]() {
        while (true) {
            resetConversation();

            // Initial input
            m_sConversationState.prompt = "Password: ";
            waitForInput();

            // For grace or SIGUSR1 unlocks
            if (g_pHyprlock->isUnlocked())
                return;

            const auto AUTHENTICATED = auth();

            // For SIGUSR1 unlocks
            if (g_pHyprlock->isUnlocked())
                return;

            if (!AUTHENTICATED)
                g_pAuth->enqueueFail(m_sConversationState.failText, AUTH_IMPL_PAM);
            else {
                g_pAuth->enqueueUnlock();
                return;
            }
        }
    });
}

bool CPam::auth() {
    const pam_conv localConv   = {.conv = conv, .appdata_ptr = (void*)&m_sConversationState};
    pam_handle_t*  handle      = nullptr;
    auto           uidPassword = getpwuid(getuid());
    RASSERT(uidPassword && uidPassword->pw_name, "Failed to get username (getpwuid)");

    int ret = pam_start(m_sPamModule.c_str(), uidPassword->pw_name, &localConv, &handle);

    if (ret != PAM_SUCCESS) {
        m_sConversationState.failText = "pam_start failed";
        Debug::log(ERR, "auth: pam_start failed for {}", m_sPamModule);
        return false;
    }

    ret = pam_authenticate(handle, 0);
    pam_end(handle, ret);
    handle = nullptr;

    m_sConversationState.waitingForPamAuth = false;

    if (ret != PAM_SUCCESS) {
        if (!m_sConversationState.failTextFromPam)
            m_sConversationState.failText = ret == PAM_AUTH_ERR ? "Authentication failed" : "pam_authenticate failed";
        Debug::log(ERR, "auth: {} for {}", m_sConversationState.failText, m_sPamModule);
        return false;
    }

    m_sConversationState.failText = "Successfully authenticated";
    Debug::log(LOG, "auth: authenticated for {}", m_sPamModule);

    return true;
}

void CPam::waitForInput() {
    std::unique_lock<std::mutex> lk(m_sConversationState.inputMutex);
    m_bBlockInput                          = false;
    m_sConversationState.waitingForPamAuth = false;
    m_sConversationState.inputRequested    = true;
    m_sConversationState.inputSubmittedCondition.wait(lk, [this] { return !m_sConversationState.inputRequested || g_pHyprlock->m_bTerminate; });
    m_bBlockInput = true;
}

void CPam::handleInput(const std::string& input) {
    std::unique_lock<std::mutex> lk(m_sConversationState.inputMutex);

    if (!m_sConversationState.inputRequested)
        Debug::log(ERR, "SubmitInput called, but the auth thread is not waiting for input!");

    m_sConversationState.input             = input;
    m_sConversationState.inputRequested    = false;
    m_sConversationState.waitingForPamAuth = true;
    m_sConversationState.inputSubmittedCondition.notify_all();
}

std::optional<std::string> CPam::getLastFailText() {
    std::lock_guard<std::mutex> lock(m_sConversationState.inputMutex);
    return m_sConversationState.failText.empty() ? std::nullopt : std::optional(m_sConversationState.failText);
}

std::optional<std::string> CPam::getLastPrompt() {
    std::lock_guard<std::mutex> lock(m_sConversationState.inputMutex);
    return m_sConversationState.prompt.empty() ? std::nullopt : std::optional(m_sConversationState.prompt);
}

bool CPam::checkWaiting() {
    std::lock_guard<std::mutex> lock(m_sConversationState.inputMutex);
    return m_bBlockInput || m_sConversationState.waitingForPamAuth;
}

void CPam::terminate() {
    m_sConversationState.inputSubmittedCondition.notify_all();
    if (m_thread.joinable())
        m_thread.join();
}

void CPam::resetConversation() {
    m_sConversationState.input             = "";
    m_sConversationState.waitingForPamAuth = false;
    m_sConversationState.inputRequested    = false;
    m_sConversationState.failTextFromPam   = false;
}
