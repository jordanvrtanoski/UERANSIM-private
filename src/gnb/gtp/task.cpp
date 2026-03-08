//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <gnb/gtp/proto.hpp>
#include <gnb/rls/task.hpp>
#include <lib/asn/utils.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>

#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>

namespace nr::gnb
{
namespace
{

uint64_t Fnv1aUpdate(uint64_t hash, const uint8_t *data, size_t length)
{
    constexpr uint64_t kFnvPrime = 1099511628211ull;
    for (size_t index = 0; index < length; index++)
    {
        hash ^= static_cast<uint64_t>(data[index]);
        hash *= kFnvPrime;
    }
    return hash;
}

uint64_t HashUplinkFlowTuple(const uint8_t *packet, size_t length)
{
    constexpr uint64_t kFnvOffsetBasis = 1469598103934665603ull;
    uint64_t hash = kFnvOffsetBasis;

    if (length == 0 || packet == nullptr)
        return hash;

    uint8_t ipVersion = static_cast<uint8_t>((packet[0] >> 4) & 0xF);
    uint8_t l4Protocol = 0;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    if (ipVersion == 4)
    {
        if (length < 20)
            return hash;

        size_t ipHeaderLength = static_cast<size_t>((packet[0] & 0x0F) * 4);
        if (ipHeaderLength < 20 || ipHeaderLength > length)
            return hash;

        l4Protocol = packet[9];
        hash = Fnv1aUpdate(hash, packet + 12, 4);
        hash = Fnv1aUpdate(hash, packet + 16, 4);

        if ((l4Protocol == 6 || l4Protocol == 17) && length >= ipHeaderLength + 4)
        {
            srcPort = static_cast<uint16_t>((packet[ipHeaderLength] << 8) | packet[ipHeaderLength + 1]);
            dstPort = static_cast<uint16_t>((packet[ipHeaderLength + 2] << 8) | packet[ipHeaderLength + 3]);
        }
    }
    else if (ipVersion == 6)
    {
        if (length < 40)
            return hash;

        l4Protocol = packet[6];
        hash = Fnv1aUpdate(hash, packet + 8, 16);
        hash = Fnv1aUpdate(hash, packet + 24, 16);

        if ((l4Protocol == 6 || l4Protocol == 17) && length >= 44)
        {
            srcPort = static_cast<uint16_t>((packet[40] << 8) | packet[41]);
            dstPort = static_cast<uint16_t>((packet[42] << 8) | packet[43]);
        }
    }
    else
    {
        return hash;
    }

    hash = Fnv1aUpdate(hash, &l4Protocol, sizeof(l4Protocol));

    uint8_t portBytes[4] = {static_cast<uint8_t>((srcPort >> 8) & 0xFF), static_cast<uint8_t>(srcPort & 0xFF),
                            static_cast<uint8_t>((dstPort >> 8) & 0xFF), static_cast<uint8_t>(dstPort & 0xFF)};
    hash = Fnv1aUpdate(hash, portBytes, sizeof(portBytes));

    return hash;
}

uint8_t SelectUplinkQfi(const PduSessionResource &session, const uint8_t *packet, size_t length)
{
    if (!session.qosFlows)
        return 0;

    std::vector<uint8_t> validQfis{};
    auto &qosList = session.qosFlows->list;
    validQfis.reserve(static_cast<size_t>(qosList.count));
    for (int index = 0; index < qosList.count; index++)
    {
        auto *qosItem = qosList.array[index];
        if (!qosItem)
            continue;
        auto qfi = static_cast<uint8_t>(qosItem->qosFlowIdentifier);
        if (qfi >= 1 && qfi <= 63)
            validQfis.push_back(qfi);
    }

    if (validQfis.empty())
        return 0;
    if (validQfis.size() == 1)
        return validQfis.front();

    uint64_t hash = HashUplinkFlowTuple(packet, length);
    return validQfis[hash % validQfis.size()];
}

} // namespace

GtpTask::GtpTask(TaskBase *base)
    : m_base{base}, m_udpServer{}, m_ueContexts{}, m_rateLimiter(std::make_unique<RateLimiter>()), m_pduSessions{},
      m_sessionTree{}
{
    m_logger = m_base->logBase->makeUniqueLogger("gtp");
}

std::optional<GtpSessionSnapshot> GtpTask::getSessionSnapshot(int ueId, int psi) const
{
    uint64_t sessionInd = MakeSessionResInd(ueId, psi);
    auto it = m_pduSessions.find(sessionInd);
    if (it == m_pduSessions.end() || !it->second)
        return std::nullopt;

    const auto &session = *it->second;
    GtpSessionSnapshot snapshot{};
    snapshot.psi = session.psi;
    snapshot.sessionType = session.sessionType;
    snapshot.sessionAmbr = session.sessionAmbr;
    snapshot.upTunnel.teid = session.upTunnel.teid;
    snapshot.upTunnel.address = session.upTunnel.address.copy();
    snapshot.downTunnel.teid = session.downTunnel.teid;
    snapshot.downTunnel.address = session.downTunnel.address.copy();

    if (session.qosFlows)
    {
        auto &qosList = session.qosFlows->list;
        for (int i = 0; i < qosList.count; i++)
            snapshot.qfis.push_back(static_cast<uint8_t>(qosList.array[i]->qosFlowIdentifier));
    }

    return snapshot;
}

void GtpTask::onStart()
{
    try
    {
        m_udpServer = new udp::UdpServerTask(m_base->config->gtpIp, cons::GtpPort, this);
        m_udpServer->start();
    }
    catch (const LibError &e)
    {
        m_logger->err("GTP/UDP task could not be created. %s", e.what());
    }
}

void GtpTask::onQuit()
{
    m_udpServer->quit();
    delete m_udpServer;

    m_ueContexts.clear();
}

void GtpTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::GNB_NGAP_TO_GTP: {
        auto &w = dynamic_cast<NmGnbNgapToGtp &>(*msg);
        switch (w.present)
        {
        case NmGnbNgapToGtp::UE_CONTEXT_UPDATE: {
            handleUeContextUpdate(*w.update);
            break;
        }
        case NmGnbNgapToGtp::UE_CONTEXT_RELEASE: {
            handleUeContextDelete(w.ueId);
            break;
        }
        case NmGnbNgapToGtp::SESSION_CREATE: {
            handleSessionCreate(w.resource);
            break;
        }
        case NmGnbNgapToGtp::SESSION_MODIFY: {
            handleSessionModify(w.resource);
            break;
        }
        case NmGnbNgapToGtp::SESSION_RELEASE: {
            handleSessionRelease(w.ueId, w.psi);
            break;
        }
        }
        break;
    }
    case NtsMessageType::GNB_RLS_TO_GTP: {
        auto &w = dynamic_cast<NmGnbRlsToGtp &>(*msg);
        switch (w.present)
        {
        case NmGnbRlsToGtp::DATA_PDU_DELIVERY: {
            handleUplinkData(w.ueId, w.psi, std::move(w.pdu));
            break;
        }
        }
        break;
    }
    case NtsMessageType::UDP_SERVER_RECEIVE:
        handleUdpReceive(dynamic_cast<udp::NwUdpServerReceive &>(*msg));
        break;
    default:
        m_logger->unhandledNts(*msg);
        break;
    }
}

void GtpTask::handleUeContextUpdate(const GtpUeContextUpdate &msg)
{
    if (!m_ueContexts.count(msg.ueId))
        m_ueContexts[msg.ueId] = std::make_unique<GtpUeContext>(msg.ueId);

    auto &ue = m_ueContexts[msg.ueId];
    ue->ueAmbr = msg.ueAmbr;

    updateAmbrForUe(ue->ueId);
}

void GtpTask::handleSessionCreate(PduSessionResource *session)
{
    if (!m_ueContexts.count(session->ueId))
    {
        m_logger->err("PDU session resource could not be created, UE context with ID[%d] not found", session->ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(session->ueId, session->psi);
    m_pduSessions[sessionInd] = std::unique_ptr<PduSessionResource>(session);

    m_sessionTree.insert(sessionInd, session->downTunnel.teid);

    updateAmbrForUe(session->ueId);
    updateAmbrForSession(sessionInd);
}

void GtpTask::handleSessionModify(PduSessionResource *session)
{
    std::unique_ptr<PduSessionResource> incoming{session};
    if (!incoming)
        return;

    if (!m_ueContexts.count(incoming->ueId))
    {
        m_logger->err("PDU session resource could not be modified, UE context with ID[%d] not found", incoming->ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(incoming->ueId, incoming->psi);
    auto it = m_pduSessions.find(sessionInd);
    if (it == m_pduSessions.end() || !it->second)
    {
        m_logger->err("PDU session resource could not be modified, session not found UE[%d] PSI[%d]", incoming->ueId,
                      incoming->psi);
        return;
    }

    auto &existing = it->second;

    if (incoming->sessionType == PduSessionType::UNSTRUCTURED)
        incoming->sessionType = existing->sessionType;

    if (incoming->sessionAmbr.ulAmbr == 0 && incoming->sessionAmbr.dlAmbr == 0)
        incoming->sessionAmbr = existing->sessionAmbr;

    if (incoming->upTunnel.teid == 0)
        incoming->upTunnel.teid = existing->upTunnel.teid;
    if (incoming->upTunnel.address.length() == 0)
        incoming->upTunnel.address = existing->upTunnel.address.copy();

    if (incoming->downTunnel.teid == 0)
        incoming->downTunnel.teid = existing->downTunnel.teid;
    if (incoming->downTunnel.address.length() == 0)
        incoming->downTunnel.address = existing->downTunnel.address.copy();

    if (!incoming->qosFlows && existing->qosFlows)
        incoming->qosFlows = asn::UniqueCopy(*existing->qosFlows, asn_DEF_ASN_NGAP_QosFlowSetupRequestList);

    uint32_t oldDownTeid = existing->downTunnel.teid;
    uint32_t newDownTeid = incoming->downTunnel.teid;

    it->second = std::move(incoming);

    if (oldDownTeid != newDownTeid)
    {
        m_sessionTree.remove(sessionInd, oldDownTeid);
        m_sessionTree.insert(sessionInd, newDownTeid);
    }

    updateAmbrForUe(GetUeId(sessionInd));
    updateAmbrForSession(sessionInd);
}

void GtpTask::handleSessionRelease(int ueId, int psi)
{
    if (!m_ueContexts.count(ueId))
    {
        m_logger->err("PDU session resource could not be released, UE context with ID[%d] not found", ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    // Remove all session information from rate limiter
    m_rateLimiter->updateSessionUplinkLimit(sessionInd, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // And remove from PDU session table
    if (m_pduSessions.count(sessionInd))
    {
        uint32_t teid = m_pduSessions[sessionInd]->downTunnel.teid;
        m_pduSessions.erase(sessionInd);

        // And remove from the tree
        m_sessionTree.remove(sessionInd, teid);
    }
}

void GtpTask::handleUeContextDelete(int ueId)
{
    // Find PDU sessions of the UE
    std::vector<uint64_t> sessions{};
    m_sessionTree.enumerateByUe(ueId, sessions);

    for (auto &session : sessions)
    {
        // Remove all session information from rate limiter
        m_rateLimiter->updateSessionUplinkLimit(session, 0);
        m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

        // And remove from PDU session table
        uint32_t teid = m_pduSessions[session]->downTunnel.teid;
        m_pduSessions.erase(session);

        // And remove from the tree
        m_sessionTree.remove(session, teid);
    }

    // Remove all user information from rate limiter
    m_rateLimiter->updateUeUplinkLimit(ueId, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // Remove UE context
    m_ueContexts.erase(ueId);
}

void GtpTask::handleUplinkData(int ueId, int psi, OctetString &&pdu)
{
    const uint8_t *data = pdu.data();

    // Ignore unknown IP versions. Allow IPv4 and IPv6.
    int ipVersion = (data[0] >> 4) & 0xF;
    if (ipVersion != 4 && ipVersion != 6)
        return;

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    if (!m_pduSessions.count(sessionInd))
    {
        m_logger->err("Uplink data failure, PDU session not found. UE[%d] PSI[%d]", ueId, psi);
        return;
    }

    auto &pduSession = m_pduSessions[sessionInd];
    m_logger->debug("UL data GTP tx UE[%d] PSI[%d] bytes[%d] teid[%u]", ueId, psi, static_cast<int>(pdu.length()),
                    pduSession->upTunnel.teid);

    if (m_rateLimiter->allowUplinkPacket(sessionInd, static_cast<int64_t>(pdu.length())))
    {
        gtp::GtpMessage gtp{};
        gtp.payload = std::move(pdu);
        gtp.msgType = gtp::GtpMessage::MT_G_PDU;
        gtp.teid = pduSession->upTunnel.teid;

        uint8_t selectedQfi = SelectUplinkQfi(*pduSession, data, static_cast<size_t>(gtp.payload.length()));
        if (selectedQfi == 0)
        {
            m_logger->err("Uplink data failure, no valid QFI for UE[%d] PSI[%d]", ueId, psi);
            return;
        }

        auto ul = std::make_unique<gtp::UlPduSessionInformation>();
        ul->qfi = static_cast<int>(selectedQfi);

        auto cont = std::make_unique<gtp::PduSessionContainerExtHeader>();
        cont->pduSessionInformation = std::move(ul);
        gtp.extHeaders.push_back(std::move(cont));

        OctetString gtpPdu;
        if (!gtp::EncodeGtpMessage(gtp, gtpPdu))
            m_logger->err("Uplink data failure, GTP encoding failed");
        else
            m_udpServer->send(InetAddress(pduSession->upTunnel.address, cons::GtpPort), gtpPdu);
    }
}

void GtpTask::handleUdpReceive(const udp::NwUdpServerReceive &msg)
{
    OctetView buffer{msg.packet};
    auto gtp = gtp::DecodeGtpMessage(buffer);

    switch (gtp->msgType)
    {
    case gtp::GtpMessage::MT_G_PDU: {
        auto sessionInd = m_sessionTree.findByDownTeid(gtp->teid);
        if (sessionInd == 0)
        {
            m_logger->err("TEID %d not found on GTP-U Downlink", gtp->teid);
            return;
        }

        if (m_rateLimiter->allowDownlinkPacket(sessionInd, gtp->payload.length()))
        {
            auto w = std::make_unique<NmGnbGtpToRls>(NmGnbGtpToRls::DATA_PDU_DELIVERY);
            w->ueId = GetUeId(sessionInd);
            w->psi = GetPsi(sessionInd);
            w->pdu = std::move(gtp->payload);
            m_base->rlsTask->push(std::move(w));
        }
        return;
    }
    case gtp::GtpMessage::MT_ECHO_REQUEST: {
        gtp::GtpMessage gtpResponse{};
        gtpResponse.msgType = gtp::GtpMessage::MT_ECHO_RESPONSE;
        gtpResponse.seq = gtp->seq;
        gtpResponse.payload = OctetString::FromOctet2({14, 0});

        OctetString gtpPdu;
        if (gtp::EncodeGtpMessage(gtpResponse, gtpPdu))
            m_udpServer->send(msg.fromAddress, gtpPdu);
        else
            m_logger->err("Uplink data failure, GTP encoding failed");
        return;
    }
    default: {
        m_logger->err("Unhandled GTP-U message type: %d", gtp->msgType);
        return;
    }
    }
}

void GtpTask::updateAmbrForUe(int ueId)
{
    if (!m_ueContexts.count(ueId))
        return;

    auto &ue = m_ueContexts[ueId];
    m_rateLimiter->updateUeUplinkLimit(ueId, ue->ueAmbr.ulAmbr);
    m_rateLimiter->updateUeDownlinkLimit(ueId, ue->ueAmbr.dlAmbr);
}

void GtpTask::updateAmbrForSession(uint64_t pduSession)
{
    if (!m_pduSessions.count(pduSession))
        return;

    auto &sess = m_pduSessions[pduSession];
    m_rateLimiter->updateSessionUplinkLimit(pduSession, sess->sessionAmbr.ulAmbr);
    m_rateLimiter->updateSessionDownlinkLimit(pduSession, sess->sessionAmbr.dlAmbr);
}

} // namespace nr::gnb
