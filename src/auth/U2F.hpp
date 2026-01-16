#pragma once

#include "Auth.hpp"

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
        std::atomic<bool> abort       = false;
        std::atomic<bool> done        = false;
        std::atomic<bool> deviceFound = false;
    } m_sState;

    std::string m_sReadyMessage;
    std::string m_sPresentMessage;

    mutable std::mutex m_stringMutex;  // Protects m_sPrompt and m_sFailureReason
    std::string        m_sPrompt{""};
    std::string        m_sFailureReason{""};

    std::thread m_pollThread;

    void pollForDevice();
    bool tryAuthenticate(const char* devicePath);
};
