#pragma once

#include "Auth.hpp"
#include "U2FCredentials.hpp"

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <atomic>
#include <fido.h>

class CU2F : public IAuthImplementation {
  public:
    CU2F();
    virtual ~CU2F();

    virtual eAuthImplementations getImplType() {
        return AUTH_IMPL_U2F;
    }
    virtual void                       init();
    virtual void                       handleInput(const std::string& input);
    virtual bool                       checkWaiting();
    virtual std::optional<std::string> getLastFailText();
    virtual std::optional<std::string> getLastPrompt();
    virtual void                       terminate();

  private:
    struct SU2FState {
        std::atomic<bool> abort         = false;
        std::atomic<bool> done          = false;
        std::atomic<bool> deviceFound   = false;
        std::atomic<bool> authenticating = false;
    } m_sState;

    // Configuration
    std::string m_sRelyingPartyId;
    std::string m_sAuthFile;
    int         m_iTimeout = 30000;  // milliseconds

    // UI messages
    std::string m_sReadyMessage;
    std::string m_sPresentMessage;
    std::string m_sVerifyingMessage;

    // Credential management
    CU2FCredentials m_credentials;

    mutable std::mutex m_stringMutex;  // Protects m_sPrompt and m_sFailureReason
    std::string        m_sPrompt{""};
    std::string        m_sFailureReason{""};

    std::thread m_pollThread;

    void pollForDevice();
    bool performAssertion(const char* devicePath);
    bool verifyAssertionSignature(fido_assert_t* assertion, const SU2FCredential& cred);

    // Generate cryptographically secure random bytes for challenge
    bool generateChallenge(unsigned char* buffer, size_t length);
};
