//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <memory>
#include <thread>
#include <ue/nts.hpp>
#include <ue/tun/task.hpp>
#include <ue/types.hpp>
#include <unordered_map>
#include <utils/logger.hpp>
#include <utils/nts.hpp>
#include <vector>

namespace nr::ue
{

class UeAppTask : public NtsTask
{
  private:
    TaskBase *m_base;
    std::unique_ptr<Logger> m_logger;

    std::array<TunTask *, 16> m_tunTasks{};
    std::array<bool, 16> m_ipv6RsInjected{}; // "attempt sequence completed"
    std::array<bool, 16> m_ipv6RsTimerArmed{};
    std::array<uint8_t, 16> m_ipv6RsAttemptsRemaining{};
    std::array<std::array<uint8_t, 8>, 16> m_ipv6RsIid{};
    ECmState m_cmState{};

    friend class UeCmdHandler;

  public:
    explicit UeAppTask(TaskBase *base);
    ~UeAppTask() override = default;

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;

  private:
    void receiveStatusUpdate(NmUeStatusUpdate &msg);
    void setupTunInterface(const PduSession *pduSession);
    void startIpv6RouterSolicitation(int psi, const uint8_t iid[8]);
    void scheduleIpv6RouterSolicitation(int psi, int delayMs);
    void trySendIpv6RouterSolicitation(int psi);
};

} // namespace nr::ue
