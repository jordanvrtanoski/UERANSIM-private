//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"
#include "cmd_handler.hpp"
#include <lib/nas/utils.hpp>
#include <ue/nas/task.hpp>
#include <ue/rls/task.hpp>
#include <ue/tun/tun.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>

#include <arpa/inet.h>
#include <cstring>

static constexpr const int SWITCH_OFF_TIMER_ID = 1;
static constexpr const int SWITCH_OFF_DELAY = 500;

namespace nr::ue
{

UeAppTask::UeAppTask(TaskBase *base) : m_base{base}
{
    m_logger = m_base->logBase->makeUniqueLogger(m_base->config->getLoggerPrefix() + "app");
}

void UeAppTask::onStart()
{
}

void UeAppTask::onQuit()
{
    for (auto &tunTask : m_tunTasks)
    {
        if (tunTask != nullptr)
        {
            tunTask->quit();
            delete tunTask;
            tunTask = nullptr;
        }
    }
}

void UeAppTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::UE_TUN_TO_APP: {
        auto &w = dynamic_cast<NmUeTunToApp &>(*msg);
        switch (w.present)
        {
        case NmUeTunToApp::DATA_PDU_DELIVERY: {
            auto m = std::make_unique<NmUeAppToNas>(NmUeAppToNas::UPLINK_DATA_DELIVERY);
            m->psi = w.psi;
            m->data = std::move(w.data);
            m_base->nasTask->push(std::move(m));
            break;
        }
        case NmUeTunToApp::TUN_ERROR: {
            m_logger->err("TUN failure [%s]", w.error.c_str());
            break;
        }
        }
        break;
    }
    case NtsMessageType::UE_NAS_TO_APP: {
        auto &w = dynamic_cast<NmUeNasToApp &>(*msg);
        switch (w.present)
        {
        case NmUeNasToApp::PERFORM_SWITCH_OFF: {
            setTimer(SWITCH_OFF_TIMER_ID, SWITCH_OFF_DELAY);
            break;
        }
        case NmUeNasToApp::DOWNLINK_DATA_DELIVERY: {
            auto *tunTask = m_tunTasks[w.psi];
            if (tunTask)
            {
                auto m = std::make_unique<NmAppToTun>(NmAppToTun::DATA_PDU_DELIVERY);
                m->psi = w.psi;
                m->data = std::move(w.data);
                tunTask->push(std::move(m));
            }
            break;
        }
        }
        break;
    }
    case NtsMessageType::UE_STATUS_UPDATE: {
        receiveStatusUpdate(dynamic_cast<NmUeStatusUpdate &>(*msg));
        break;
    }
    case NtsMessageType::UE_CLI_COMMAND: {
        auto &w = dynamic_cast<NmUeCliCommand &>(*msg);
        UeCmdHandler handler{m_base};
        handler.handleCmd(w);
        break;
    }
    case NtsMessageType::TIMER_EXPIRED: {
        auto &w = dynamic_cast<NmTimerExpired &>(*msg);
        if (w.timerId == SWITCH_OFF_TIMER_ID)
        {
            m_logger->info("UE device is switching off");
            m_base->ueController->performSwitchOff(m_base->ue);
        }
        break;
    }
    default:
        m_logger->unhandledNts(*msg);
        break;
    }
}

void UeAppTask::receiveStatusUpdate(NmUeStatusUpdate &msg)
{
    if (msg.what == NmUeStatusUpdate::SESSION_ESTABLISHMENT)
    {
        auto *session = msg.pduSession;

        setupTunInterface(session);
        return;
    }

    if (msg.what == NmUeStatusUpdate::SESSION_RELEASE)
    {
        if (m_tunTasks[msg.psi] != nullptr)
        {
            m_tunTasks[msg.psi]->quit();
            delete m_tunTasks[msg.psi];
            m_tunTasks[msg.psi] = nullptr;
        }

        return;
    }

    if (msg.what == NmUeStatusUpdate::CM_STATE)
    {
        m_cmState = msg.cmState;
        return;
    }
}

void UeAppTask::setupTunInterface(const PduSession *pduSession)
{
    if (!utils::IsRoot())
    {
        m_logger->err("TUN interface could not be setup. Permission denied. Please run the UE with 'sudo'");
        return;
    }

    if (!pduSession->pduAddress.has_value())
    {
        m_logger->err("Connection could not setup. PDU address is missing.");
        return;
    }

    if (pduSession->pduAddress->sessionType != pduSession->sessionType)
    {
        m_logger->err("Connection could not setup. PDU session type mismatch. sessionType[%s] pduAddressType[%s].",
                      nas::utils::EnumToString(pduSession->sessionType),
                      nas::utils::EnumToString(pduSession->pduAddress->sessionType));
        return;
    }

    auto sessionType = pduSession->sessionType;
    if (sessionType != nas::EPduSessionType::IPV4 && sessionType != nas::EPduSessionType::IPV6 &&
        sessionType != nas::EPduSessionType::IPV4V6)
    {
        m_logger->err("Connection could not setup. PDU session type [%s] is not supported.",
                      nas::utils::EnumToString(sessionType));
        return;
    }

    int psi = pduSession->psi;
    if (psi == 0 || psi > 15)
    {
        m_logger->err("Connection could not setup. Invalid PSI.");
        return;
    }

    if (m_tunTasks[psi] != nullptr)
    {
        m_logger->err("Connection could not setup. TUN task for specified PSI is non-null.");
        return;
    }

    std::string error{}, allocatedName{};
    std::string requestedName = cons::TunNamePrefix;
    std::string requestedNetmask = cons::TunNetmask;
    if (m_base->config->tunName.has_value())
        requestedName = *m_base->config->tunName;
    if (m_base->config->tunNetmask.has_value())
        requestedNetmask = *m_base->config->tunNetmask;
    
    int fd = tun::TunAllocate(requestedName.c_str(), allocatedName, error);
    if (fd == 0 || error.length() > 0)
    {
        m_logger->err("TUN allocation failure [%s]", error.c_str());
        return;
    }

    const auto &pduAddrInfo = pduSession->pduAddress->pduAddressInformation;
    std::string ipv4Address{};
    std::string ipv6Address{};
    std::string ipv6LinkLocal{};

    auto inetToString = [](int af, const void *src) -> std::string {
        char buf[INET6_ADDRSTRLEN] = {0};
        if (inet_ntop(af, src, buf, sizeof(buf)) == nullptr)
            return {};
        return std::string{buf};
    };

    auto ipv6LinkLocalFromIid = [&](const uint8_t *iid) -> std::string {
        in6_addr a{};
        a.s6_addr[0] = 0xfe;
        a.s6_addr[1] = 0x80;
        std::memcpy(a.s6_addr + 8, iid, 8);
        return inetToString(AF_INET6, &a);
    };

    if (sessionType == nas::EPduSessionType::IPV4)
    {
        if (pduAddrInfo.length() != 4)
        {
            m_logger->err("Connection could not setup. Unexpected PDU IPv4 address length[%d].",
                          static_cast<int>(pduAddrInfo.length()));
            return;
        }
        ipv4Address = inetToString(AF_INET, pduAddrInfo.data());
        if (ipv4Address.empty())
        {
            m_logger->err("Connection could not setup. Invalid PDU IPv4 address.");
            return;
        }

        bool r = tun::TunConfigure(allocatedName, ipv4Address, requestedNetmask, cons::TunMtu,
                                   m_base->config->configureRouting, error);
        if (!r || !error.empty())
        {
            m_logger->err("TUN configuration failure [%s]", error.c_str());
            return;
        }
    }
    else if (sessionType == nas::EPduSessionType::IPV6)
    {
        if (pduAddrInfo.length() == 16)
        {
            ipv6Address = inetToString(AF_INET6, pduAddrInfo.data());
        }
        else if (pduAddrInfo.length() == 8)
        {
            // TS 24.501: for IPv6 PDU session type, network may provide only the interface identifier.
            ipv6LinkLocal = ipv6LinkLocalFromIid(pduAddrInfo.data());
            if (!ipv6LinkLocal.empty())
                m_logger->debug("PDU IPv6 address provided as interface identifier (8 octets). Using link-local[%s].",
                                ipv6LinkLocal.c_str());
        }
        else
        {
            m_logger->err("Connection could not setup. Unexpected PDU IPv6 address length[%d] value[%s].",
                          static_cast<int>(pduAddrInfo.length()), pduAddrInfo.toHexString().c_str());
            return;
        }

        if (ipv6Address.empty() && ipv6LinkLocal.empty())
        {
            m_logger->err("Connection could not setup. Invalid PDU IPv6 address.");
            return;
        }

        if (!ipv6LinkLocal.empty())
        {
            std::string errorLl{};
            bool rLl = tun::TunConfigure6(allocatedName, ipv6LinkLocal, 64, cons::TunMtu, m_base->config->configureRouting,
                                          errorLl);
            if (!rLl || !errorLl.empty())
            {
                m_logger->err("TUN IPv6 link-local configuration failure [%s]", errorLl.c_str());
                return;
            }
        }

        if (!ipv6Address.empty())
        {
            int prefix = m_base->config->tunIpv6Prefix.value_or(64);
            bool r = tun::TunConfigure6(allocatedName, ipv6Address, prefix, cons::TunMtu, m_base->config->configureRouting,
                                        error);
            if (!r || !error.empty())
            {
                m_logger->err("TUN configuration failure [%s]", error.c_str());
                return;
            }
        }
    }
    else // IPV4V6
    {
        if (pduAddrInfo.length() == 20)
        {
            ipv4Address = inetToString(AF_INET, pduAddrInfo.data());
            ipv6Address = inetToString(AF_INET6, pduAddrInfo.data() + 4);
        }
        else if (pduAddrInfo.length() == 12)
        {
            // TS 24.501: for IPv4v6, network may provide IPv4 address + IPv6 interface identifier.
            ipv4Address = inetToString(AF_INET, pduAddrInfo.data());
            ipv6LinkLocal = ipv6LinkLocalFromIid(pduAddrInfo.data() + 4);
            if (!ipv6LinkLocal.empty())
                m_logger->debug("PDU IPv6 address in IPv4v6 provided as interface identifier (8 octets). Using link-local[%s].",
                                ipv6LinkLocal.c_str());
        }
        else
        {
            m_logger->err("Connection could not setup. Unexpected PDU IPv4v6 address length[%d] value[%s].",
                          static_cast<int>(pduAddrInfo.length()), pduAddrInfo.toHexString().c_str());
            return;
        }

        if (ipv4Address.empty())
        {
            m_logger->err("Connection could not setup. Invalid PDU IPv4v6 address.");
            return;
        }
        if (ipv6Address.empty() && ipv6LinkLocal.empty())
        {
            m_logger->err("Connection could not setup. Invalid PDU IPv6 address in IPv4v6 PDU address.");
            return;
        }

        bool r4 = tun::TunConfigure(allocatedName, ipv4Address, requestedNetmask, cons::TunMtu,
                                    m_base->config->configureRouting, error);
        if (!r4 || !error.empty())
        {
            m_logger->err("TUN configuration failure [%s]", error.c_str());
            return;
        }

        if (!ipv6LinkLocal.empty())
        {
            std::string errorLl{};
            bool rLl = tun::TunConfigure6(allocatedName, ipv6LinkLocal, 64, cons::TunMtu, m_base->config->configureRouting,
                                          errorLl);
            if (!rLl || !errorLl.empty())
            {
                m_logger->err("TUN IPv6 link-local configuration failure [%s]", errorLl.c_str());
                return;
            }
        }

        if (!ipv6Address.empty())
        {
            int prefix = m_base->config->tunIpv6Prefix.value_or(64);
            std::string error6{};
            bool r6 = tun::TunConfigure6(allocatedName, ipv6Address, prefix, cons::TunMtu, m_base->config->configureRouting,
                                         error6);
            if (!r6 || !error6.empty())
            {
                m_logger->err("TUN IPv6 configuration failure [%s]", error6.c_str());
                return;
            }
        }
    }

    auto *task = new TunTask(m_base, psi, fd);
    m_tunTasks[psi] = task;
    task->start();

    if (sessionType == nas::EPduSessionType::IPV4)
    {
        m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s] is up.",
                       pduSession->psi, allocatedName.c_str(), ipv4Address.c_str());
    }
    else if (sessionType == nas::EPduSessionType::IPV6)
    {
        if (!ipv6Address.empty())
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s/%d] is up.",
                           pduSession->psi, allocatedName.c_str(), ipv6Address.c_str(),
                           m_base->config->tunIpv6Prefix.value_or(64));
        }
        else
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s] is up.",
                           pduSession->psi, allocatedName.c_str(), ipv6LinkLocal.c_str());
        }
    }
    else
    {
        if (!ipv6Address.empty())
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s, %s/%d] is up.",
                           pduSession->psi, allocatedName.c_str(), ipv4Address.c_str(), ipv6Address.c_str(),
                           m_base->config->tunIpv6Prefix.value_or(64));
        }
        else
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s, %s] is up.",
                           pduSession->psi, allocatedName.c_str(), ipv4Address.c_str(), ipv6LinkLocal.c_str());
        }
    }
}

} // namespace nr::ue
