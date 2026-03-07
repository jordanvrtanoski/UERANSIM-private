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
#include <cstdio>
#include <cstring>

static constexpr const int SWITCH_OFF_TIMER_ID = 1;
static constexpr const int SWITCH_OFF_DELAY = 500;
static constexpr const int IPV6_RS_TIMER_BASE = 100;
static constexpr const int DEFAULT_IPV6_RS_RETRY_COUNT = 2;     // total attempts = 1 + retry count
static constexpr const int DEFAULT_IPV6_RS_RETRY_PERIOD_MS = 1000;

namespace nr::ue
{

static uint16_t OnesComplementChecksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i = 0;

    while (i + 1 < len)
    {
        sum += static_cast<uint16_t>((static_cast<uint16_t>(data[i]) << 8) | static_cast<uint16_t>(data[i + 1]));
        i += 2;
    }
    if (i < len)
        sum += static_cast<uint16_t>(static_cast<uint16_t>(data[i]) << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}

static OctetString BuildIpv6RouterSolicitation(const uint8_t iid[8])
{
    // Minimal IPv6 Router Solicitation (RFC4861), carried over the PDU session user-plane.
    // Open5GS SMF detects RS and responds with RA that contains the /64 prefix for SLAAC.
    //
    // IPv6 header (40) + ICMPv6 RS header (8)
    // - src: fe80::IID
    // - dst: ff02::2 (all-routers multicast)
    // - next: 58 (ICMPv6)
    // - hop limit: 255
    // Note: Open5GS RS detection does not depend on checksum, but compute it for correctness/interoperability.
    uint8_t buf[48] = {0};

    buf[0] = 0x60; // version 6
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x01;

    // payload length: 8 bytes
    buf[4] = 0x00;
    buf[5] = 0x08;
    buf[6] = 0x3a; // next header: ICMPv6 (58)
    buf[7] = 0xff; // hop limit: 255

    // src: fe80::/64 + IID
    buf[8] = 0xfe;
    buf[9] = 0x80;
    std::memcpy(buf + 16, iid, 8);

    // dst: ff02::2
    buf[24] = 0xff;
    buf[25] = 0x02;
    buf[39] = 0x02;

    // ICMPv6 Router Solicitation
    buf[40] = 133; // type: ND_ROUTER_SOLICIT
    buf[41] = 0;   // code
    // checksum (42-43) computed below
    // reserved (44-47) left 0

    // ICMPv6 checksum with pseudo-header.
    uint8_t pseudo[40 + 8] = {0};
    // src
    std::memcpy(pseudo + 0, buf + 8, 16);
    // dst
    std::memcpy(pseudo + 16, buf + 24, 16);
    // length (32-bit)
    pseudo[32] = 0x00;
    pseudo[33] = 0x00;
    pseudo[34] = 0x00;
    pseudo[35] = 0x08;
    // next header
    pseudo[39] = 0x3a;
    // icmpv6 payload
    std::memcpy(pseudo + 40, buf + 40, 8);

    uint16_t csum = OnesComplementChecksum(pseudo, sizeof(pseudo));
    buf[42] = static_cast<uint8_t>((csum >> 8) & 0xFF);
    buf[43] = static_cast<uint8_t>(csum & 0xFF);

    return OctetString::FromArray(buf, sizeof(buf));
}

static std::string DescribeIpPacket(const OctetString &data)
{
    if (data.length() == 0)
        return "len=0";

    const auto *buf = data.data();
    int ipVersion = (buf[0] >> 4) & 0xF;
    std::string desc = "len=" + std::to_string(data.length()) + " ipver=" + std::to_string(ipVersion);

    char src[INET6_ADDRSTRLEN] = {0};
    char dst[INET6_ADDRSTRLEN] = {0};
    if (ipVersion == 4 && data.length() >= 20)
    {
        inet_ntop(AF_INET, buf + 12, src, sizeof(src));
        inet_ntop(AF_INET, buf + 16, dst, sizeof(dst));
        desc += " src=" + std::string(src) + " dst=" + std::string(dst);
    }
    else if (ipVersion == 6 && data.length() >= 40)
    {
        inet_ntop(AF_INET6, buf + 8, src, sizeof(src));
        inet_ntop(AF_INET6, buf + 24, dst, sizeof(dst));
        desc += " src=" + std::string(src) + " dst=" + std::string(dst);
    }
    return desc;
}

UeAppTask::UeAppTask(TaskBase *base) : m_base{base}
{
    m_logger = m_base->logBase->makeUniqueLogger(m_base->config->getLoggerPrefix() + "app");
    m_sessionTypes.fill(nas::EPduSessionType::UNSTRUCTURED);
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
            m_logger->debug("UL packet from TUN psi[%d] %s", w.psi, DescribeIpPacket(w.data).c_str());
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
                if (w.data.length() >= 48)
                {
                    const uint8_t *buf = w.data.data();
                    if ((buf[0] >> 4) == 6 && buf[6] == 58)
                    {
                        uint8_t icmpType = buf[40];
                        if (icmpType == 134 && !m_ipv6RaSeen[w.psi])
                        {
                            m_ipv6RaSeen[w.psi] = true;
                            m_logger->info("IPv6 Router Advertisement received on PSI[%d]", w.psi);
                            if (isIpv6Ready(w.psi, true))
                            {
                                m_ipv6RsInjected[w.psi] = true;
                                m_logger->info("IPv6 is ready on PSI[%d], stopping RS retries", w.psi);
                            }
                            else
                            {
                                m_logger->debug("IPv6 RA observed on PSI[%d], but address/route readiness is still pending",
                                                w.psi);
                                scheduleIpv6RouterSolicitation(w.psi, 0);
                            }
                        }
                    }
                }
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
            break;
        }
        if (w.timerId >= IPV6_RS_TIMER_BASE && w.timerId < IPV6_RS_TIMER_BASE + 16)
        {
            int psi = w.timerId - IPV6_RS_TIMER_BASE;
            m_ipv6RsTimerArmed[psi] = false;
            trySendIpv6RouterSolicitation(psi);
            break;
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
        m_ipv6RsInjected[msg.psi] = false;
        m_ipv6RsTimerArmed[msg.psi] = false;
        m_ipv6RsAttemptsRemaining[msg.psi] = 0;
        m_ipv6RsRepeatUntilRa[msg.psi] = false;
        m_ipv6RaSeen[msg.psi] = false;
        m_ipv6ReadyLogged[msg.psi] = false;
        m_sessionTypes[msg.psi] = nas::EPduSessionType::UNSTRUCTURED;
        m_tunNames[msg.psi].clear();

        return;
    }

    if (msg.what == NmUeStatusUpdate::CM_STATE)
    {
        m_cmState = msg.cmState;
        if (m_cmState == ECmState::CM_CONNECTED)
        {
            for (int psi = 1; psi <= 15; ++psi)
            {
                if (m_ipv6RsInjected[psi])
                    continue;
                if (m_ipv6RsAttemptsRemaining[psi] == 0)
                    continue;
                scheduleIpv6RouterSolicitation(psi, 0);
            }
        }
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
    std::optional<std::string> requestedExactName{};
    if (m_base->config->tunName.has_value())
        requestedName = *m_base->config->tunName;
    if (m_base->config->tunNetmask.has_value())
        requestedNetmask = *m_base->config->tunNetmask;

    if (m_base->config->ueTag.has_value())
    {
        char ifName[32] = {0};
        std::snprintf(ifName, sizeof(ifName), "ut%04dp%02dq00", m_base->config->ueTag.value(), psi);
        requestedExactName = std::string{ifName};
    }

    int fd = requestedExactName.has_value() ? tun::TunAllocateNamed(requestedExactName.value(), allocatedName, error)
                                            : tun::TunAllocate(requestedName.c_str(), allocatedName, error);
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
        enum class IPv4v6PduAddressOrder
        {
            IPv4ThenIPv6,
            IPv6ThenIPv4,
        };

        std::optional<IPv4v6PduAddressOrder> order{};

        if (pduAddrInfo.length() == 20)
        {
            auto v4First = inetToString(AF_INET, pduAddrInfo.data());
            auto v6After = inetToString(AF_INET6, pduAddrInfo.data() + 4);

            auto v6First = inetToString(AF_INET6, pduAddrInfo.data());
            auto v4After = inetToString(AF_INET, pduAddrInfo.data() + 16);

            // Prefer the layout where IPv4 is not 0.0.0.0.
            if (!v4First.empty() && v4First != "0.0.0.0")
            {
                order = IPv4v6PduAddressOrder::IPv4ThenIPv6;
                ipv4Address = v4First;
                ipv6Address = v6After;
            }
            else if (!v4After.empty() && v4After != "0.0.0.0")
            {
                order = IPv4v6PduAddressOrder::IPv6ThenIPv4;
                ipv4Address = v4After;
                ipv6Address = v6First;
            }
            else
            {
                // Fallback: keep the legacy interpretation.
                order = IPv4v6PduAddressOrder::IPv4ThenIPv6;
                ipv4Address = v4First;
                ipv6Address = v6After;
            }
        }
        else if (pduAddrInfo.length() == 12)
        {
            // TS 24.501: for IPv4v6, network may provide an IPv6 interface identifier (8 octets) instead of full IPv6.
            // Implementations differ on the ordering of IPv4 and IID. Support both:
            // - IPv4(4) + IID(8)
            // - IID(8) + IPv4(4)
            auto v4First = inetToString(AF_INET, pduAddrInfo.data());
            auto llAfter = ipv6LinkLocalFromIid(pduAddrInfo.data() + 4);

            auto v4After = inetToString(AF_INET, pduAddrInfo.data() + 8);
            auto llFirst = ipv6LinkLocalFromIid(pduAddrInfo.data());

            if (!v4First.empty() && v4First != "0.0.0.0")
            {
                order = IPv4v6PduAddressOrder::IPv4ThenIPv6;
                ipv4Address = v4First;
                ipv6LinkLocal = llAfter;
            }
            else if (!v4After.empty() && v4After != "0.0.0.0")
            {
                order = IPv4v6PduAddressOrder::IPv6ThenIPv4;
                ipv4Address = v4After;
                ipv6LinkLocal = llFirst;
            }
            else
            {
                order = IPv4v6PduAddressOrder::IPv4ThenIPv6;
                ipv4Address = v4First;
                ipv6LinkLocal = llAfter;
            }

            if (!ipv6LinkLocal.empty())
                m_logger->debug(
                    "PDU IPv6 address in IPv4v6 provided as interface identifier (8 octets). Using link-local[%s].",
                    ipv6LinkLocal.c_str());
        }
        else
        {
            m_logger->err("Connection could not setup. Unexpected PDU IPv4v6 address length[%d] value[%s].",
                          static_cast<int>(pduAddrInfo.length()), pduAddrInfo.toHexString().c_str());
            return;
        }

        bool hasIpv4 = !ipv4Address.empty() && ipv4Address != "0.0.0.0";
        if (!hasIpv4)
        {
            m_logger->err("Connection could not setup. Invalid PDU IPv4 address in IPv4v6 PDU address. "
                          "pduAddressInformation[%s].",
                          pduAddrInfo.toHexString().c_str());
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

        // Align IPv6 RS injection with the ordering used by the network for IPv4v6 PDU address.
        // We persist the derived IID into the PDU address information itself via the existing RS logic below.
        (void)order;
    }

    auto *task = new TunTask(m_base, psi, fd);
    m_tunTasks[psi] = task;
    m_sessionTypes[psi] = sessionType;
    m_tunNames[psi] = allocatedName;
    m_ipv6ReadyLogged[psi] = false;
    task->start();

    // Trigger SLAAC/RA for IPv6-capable sessions (Open5GS sends IID in NAS and expects RS to trigger RA).
    if (!m_ipv6RsInjected[psi] &&
        (sessionType == nas::EPduSessionType::IPV6 || sessionType == nas::EPduSessionType::IPV4V6))
    {
        uint8_t iid[8] = {0};
        bool hasIid = false;

        if (sessionType == nas::EPduSessionType::IPV6)
        {
            if (pduAddrInfo.length() == 8)
            {
                std::memcpy(iid, pduAddrInfo.data(), 8);
                hasIid = true;
            }
            else if (pduAddrInfo.length() == 16)
            {
                std::memcpy(iid, pduAddrInfo.data() + 8, 8);
                hasIid = true;
            }
        }
        else // IPV4V6
        {
            if (pduAddrInfo.length() == 12)
            {
                // Support both IPv4(4)+IID(8) and IID(8)+IPv4(4) orderings.
                auto v4First = inetToString(AF_INET, pduAddrInfo.data());
                auto v4After = inetToString(AF_INET, pduAddrInfo.data() + 8);

                if (!v4First.empty() && v4First != "0.0.0.0")
                    std::memcpy(iid, pduAddrInfo.data() + 4, 8);
                else if (!v4After.empty() && v4After != "0.0.0.0")
                    std::memcpy(iid, pduAddrInfo.data(), 8);
                else
                    std::memcpy(iid, pduAddrInfo.data() + 4, 8);

                hasIid = true;
            }
            else if (pduAddrInfo.length() == 20)
            {
                // Support both IPv4(4)+IPv6(16) and IPv6(16)+IPv4(4) orderings.
                auto v4First = inetToString(AF_INET, pduAddrInfo.data());
                auto v4After = inetToString(AF_INET, pduAddrInfo.data() + 16);

                if (!v4First.empty() && v4First != "0.0.0.0")
                    std::memcpy(iid, pduAddrInfo.data() + 12, 8);
                else if (!v4After.empty() && v4After != "0.0.0.0")
                    std::memcpy(iid, pduAddrInfo.data() + 8, 8);
                else
                    std::memcpy(iid, pduAddrInfo.data() + 12, 8);

                hasIid = true;
            }
        }

        if (hasIid)
        {
            bool repeatUntilRa = true;
            startIpv6RouterSolicitation(psi, iid, repeatUntilRa);
        }
        else
            m_logger->debug("Skipping IPv6 RS injection for PSI[%d]. Cannot derive IID from PDU address length[%d].", psi,
                            static_cast<int>(pduAddrInfo.length()));
    }

    if (sessionType == nas::EPduSessionType::IPV4)
    {
        m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s] is up.",
                       pduSession->psi, allocatedName.c_str(), ipv4Address.c_str());
    }
    else if (sessionType == nas::EPduSessionType::IPV6)
    {
        if (!ipv6Address.empty())
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s/%d] is up. IPv6 route readiness pending.",
                           pduSession->psi, allocatedName.c_str(), ipv6Address.c_str(),
                           m_base->config->tunIpv6Prefix.value_or(64));
        }
        else
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s] is up. IPv6 route readiness pending.",
                           pduSession->psi, allocatedName.c_str(), ipv6LinkLocal.c_str());
        }
    }
    else
    {
        const char *ipv4Display = ipv4Address.empty() ? "none" : ipv4Address.c_str();
        if (!ipv6Address.empty())
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s, %s/%d] is up. IPv6 route readiness pending.",
                           pduSession->psi, allocatedName.c_str(), ipv4Display, ipv6Address.c_str(),
                           m_base->config->tunIpv6Prefix.value_or(64));
        }
        else
        {
            m_logger->info("Connection setup for PDU session[%d] is successful, TUN interface[%s, %s, %s] is up. IPv6 route readiness pending.",
                           pduSession->psi, allocatedName.c_str(), ipv4Display, ipv6LinkLocal.c_str());
        }
    }
}

void UeAppTask::startIpv6RouterSolicitation(int psi, const uint8_t iid[8], bool repeatUntilRa)
{
    if (psi <= 0 || psi > 15)
        return;
    if (m_ipv6RsInjected[psi])
        return;

    std::memcpy(m_ipv6RsIid[psi].data(), iid, 8);
    m_ipv6RaSeen[psi] = false;
    m_ipv6RsRepeatUntilRa[psi] = repeatUntilRa;
    int retries = m_base->config->ipv6RsRetryCount.value_or(DEFAULT_IPV6_RS_RETRY_COUNT);
    if (retries < 0)
        retries = 0;
    if (retries > 20)
        retries = 20;
    m_ipv6RsAttemptsRemaining[psi] = static_cast<uint8_t>(1 + retries);

    scheduleIpv6RouterSolicitation(psi, 0);
}

void UeAppTask::scheduleIpv6RouterSolicitation(int psi, int delayMs)
{
    if (psi <= 0 || psi > 15)
        return;
    if (m_ipv6RsInjected[psi])
        return;
    if (m_ipv6RsTimerArmed[psi])
        return;

    setTimer(IPV6_RS_TIMER_BASE + psi, delayMs);
    m_ipv6RsTimerArmed[psi] = true;
}

void UeAppTask::trySendIpv6RouterSolicitation(int psi)
{
    if (psi <= 0 || psi > 15)
        return;
    if (m_ipv6RsInjected[psi])
        return;

    if (isIpv6Ready(psi, true))
    {
        m_ipv6RsInjected[psi] = true;
        return;
    }

    if (m_ipv6RsAttemptsRemaining[psi] == 0)
    {
        if (m_ipv6RsRepeatUntilRa[psi] && !m_ipv6RaSeen[psi])
        {
            m_logger->debug("IPv6 RS: no RA yet for PSI[%d], continuing retries", psi);
            m_ipv6RsAttemptsRemaining[psi] = 1;
        }
        else if (m_ipv6RsRepeatUntilRa[psi] && m_ipv6RaSeen[psi])
        {
            m_logger->debug("IPv6 RS: RA seen on PSI[%d], but interface is not ready yet; continuing retries", psi);
            m_ipv6RsAttemptsRemaining[psi] = 1;
        }
        else
        {
            m_ipv6RsInjected[psi] = true;
            return;
        }
    }

    // NAS will drop uplink PDUs when CM is not connected; defer/retry.
    if (m_cmState != ECmState::CM_CONNECTED)
    {
        int delayMs = m_base->config->ipv6RsRetryPeriodMs.value_or(DEFAULT_IPV6_RS_RETRY_PERIOD_MS);
        scheduleIpv6RouterSolicitation(psi, delayMs);
        return;
    }

    auto rs = BuildIpv6RouterSolicitation(m_ipv6RsIid[psi].data());

    auto m = std::make_unique<NmUeAppToNas>(NmUeAppToNas::UPLINK_DATA_DELIVERY);
    m->psi = psi;
    m->data = std::move(rs);

    m_logger->debug("Injecting IPv6 Router Solicitation on PSI[%d] to trigger RA/SLAAC. Remaining[%u].", psi,
                    static_cast<unsigned>(m_ipv6RsAttemptsRemaining[psi]));
    m_base->nasTask->push(std::move(m));

    m_ipv6RsAttemptsRemaining[psi]--;
    int delayMs = m_base->config->ipv6RsRetryPeriodMs.value_or(DEFAULT_IPV6_RS_RETRY_PERIOD_MS);
    scheduleIpv6RouterSolicitation(psi, delayMs);
}

bool UeAppTask::isIpv6Ready(int psi, bool logState)
{
    if (psi <= 0 || psi > 15)
        return false;
    if (m_tunNames[psi].empty())
        return false;
    if (m_sessionTypes[psi] != nas::EPduSessionType::IPV6 && m_sessionTypes[psi] != nas::EPduSessionType::IPV4V6)
        return false;

    bool hasGlobalAddress = false;
    bool hasDefaultRoute = false;
    std::string error;
    if (!tun::TunQueryIpv6Status(m_tunNames[psi], hasGlobalAddress, hasDefaultRoute, error))
    {
        if (logState)
            m_logger->warn("IPv6 readiness probe failed for PSI[%d] interface[%s]: %s", psi, m_tunNames[psi].c_str(),
                           error.c_str());
        return false;
    }

    bool ready = hasGlobalAddress && hasDefaultRoute;
    if (ready && !m_ipv6ReadyLogged[psi])
    {
        m_logger->info("IPv6 readiness achieved on PSI[%d] interface[%s]: global address and default route present", psi,
                       m_tunNames[psi].c_str());
        m_ipv6ReadyLogged[psi] = true;
    }
    else if (!ready && logState)
    {
        m_logger->debug("IPv6 readiness pending on PSI[%d] interface[%s]: global_address[%s] default_route[%s]", psi,
                        m_tunNames[psi].c_str(), hasGlobalAddress ? "yes" : "no", hasDefaultRoute ? "yes" : "no");
    }

    return ready;
}

} // namespace nr::ue
