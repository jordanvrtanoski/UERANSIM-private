//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <cstring>
#include <unordered_set>
#include <vector>

#include <lib/asn/xnap.hpp>
#include <lib/rls/ho_phase1.hpp>
#include <lib/rrc/encode.hpp>
#include <asn/rrc/ASN_RRC_CellGroupConfig.h>
#include <asn/rrc/ASN_RRC_HandoverCommand-IEs.h>
#include <asn/rrc/ASN_RRC_HandoverCommand.h>
#include <asn/rrc/ASN_RRC_ReconfigurationWithSync.h>
#include <asn/rrc/ASN_RRC_RRCReconfiguration-IEs.h>
#include <asn/rrc/ASN_RRC_RRCReconfiguration.h>
#include <asn/rrc/ASN_RRC_ServingCellConfigCommon.h>
#include <asn/rrc/ASN_RRC_SpCellConfig.h>
#include <gnb/gtp/task.hpp>
#include <gnb/ngap/task.hpp>
#include <gnb/rls/task.hpp>
#include <gnb/rrc/task.hpp>
#include <gnb/sctp/task.hpp>
#include <utils/common.hpp>

namespace nr::gnb
{

static std::optional<uint32_t> Ho1TokenToU32(const OctetString &tokenBytes)
{
    if (tokenBytes.length() != 4)
        return std::nullopt;
    return tokenBytes.get4UI(0);
}

static int CellIdFromNci(int64_t nci, int gnbIdLength)
{
    int cellBits = 36 - gnbIdLength;
    if (cellBits <= 0 || cellBits > 36)
        return 0;
    uint64_t mask = (1ULL << cellBits) - 1ULL;
    return static_cast<int>(static_cast<uint64_t>(nci) & mask);
}

static bool IsValidHoSessionType(uint8_t sessionType)
{
    auto type = static_cast<PduSessionType>(sessionType);
    return type == PduSessionType::IPv4 || type == PduSessionType::IPv6 || type == PduSessionType::IPv4v6;
}

static bool IsValidTnlAddressLength(int len)
{
    return len == 4 || len == 16;
}

static bool IsValidQfi(uint8_t qfi)
{
    return qfi >= 1 && qfi <= 63;
}

static OctetString BuildRrcReconfigurationForHandover(int ueId, int64_t targetNci)
{
    auto *cellGroup = asn::New<ASN_RRC_CellGroupConfig>();
    cellGroup->cellGroupId = 0;
    cellGroup->spCellConfig = asn::New<ASN_RRC_SpCellConfig>();
    cellGroup->spCellConfig->reconfigurationWithSync = asn::New<ASN_RRC_ReconfigurationWithSync>();

    auto *sync = cellGroup->spCellConfig->reconfigurationWithSync;
    sync->spCellConfigCommon = asn::New<ASN_RRC_ServingCellConfigCommon>();
    sync->spCellConfigCommon->physCellId = asn::New<ASN_RRC_PhysCellId_t>();
    *sync->spCellConfigCommon->physCellId = utils::DerivePhysCellIdFromNci(targetNci);
    sync->spCellConfigCommon->dmrs_TypeA_Position = ASN_RRC_ServingCellConfigCommon__dmrs_TypeA_Position_pos2;
    sync->spCellConfigCommon->ss_PBCH_BlockPower = 0;
    sync->newUE_Identity = static_cast<long>(ueId & 0xFFFF);
    sync->t304 = ASN_RRC_ReconfigurationWithSync__t304_ms1000;

    OctetString encodedCg = rrc::encode::EncodeS(asn_DEF_ASN_RRC_CellGroupConfig, cellGroup);
    asn::Free(asn_DEF_ASN_RRC_CellGroupConfig, cellGroup);

    auto *reconfig = asn::New<ASN_RRC_RRCReconfiguration>();
    reconfig->rrc_TransactionIdentifier = 0;
    reconfig->criticalExtensions.present = ASN_RRC_RRCReconfiguration__criticalExtensions_PR_rrcReconfiguration;
    reconfig->criticalExtensions.choice.rrcReconfiguration = asn::New<ASN_RRC_RRCReconfiguration_IEs>();
    reconfig->criticalExtensions.choice.rrcReconfiguration->secondaryCellGroup = asn::New<OCTET_STRING_t>();
    asn::SetOctetString(*reconfig->criticalExtensions.choice.rrcReconfiguration->secondaryCellGroup, encodedCg);

    OctetString encoded = rrc::encode::EncodeS(asn_DEF_ASN_RRC_RRCReconfiguration, reconfig);
    asn::Free(asn_DEF_ASN_RRC_RRCReconfiguration, reconfig);
    return encoded;
}

XnTask::XnTask(TaskBase *base) : m_base(base)
{
    m_logger = base->logBase->makeUniqueLogger("xn");
}

void XnTask::onNgapPathSwitchResult(uint32_t token, bool success, int ueId)
{
    auto tgtIt = m_targetHoByToken.find(token);
    if (tgtIt == m_targetHoByToken.end())
        return;

    auto &txn = tgtIt->second;
    if (ueId > 0 && txn.ueId == 0)
        txn.ueId = ueId;

    if (!success)
    {
        m_logger->warn("Xn path switch result rx token[%u] ue[%d] result[failure] action[target_release]", token,
                       ueId > 0 ? ueId : txn.ueId);

        auto peerIt = m_peers.find(txn.peerClientId);
        if (peerIt != m_peers.end() && peerIt->second.state == EXnPeerState::CONNECTED && peerIt->second.setupCompleted)
        {
            asn::xnap::UeContextReleaseFields release{};
            release.oldUeXnapId = txn.oldUeXnapId;
            release.newUeXnapId = txn.newUeXnapId;
            release.cause = asn::xnap::XnapCause::Unspecified;
            sendUeContextRelease(peerIt->second, release, txn.token, 0);
            txn.contextReleaseSent = true;
            m_logger->info("Xn UE context release tx token[%u] ue[%d] cause[%s]", token,
                           ueId > 0 ? ueId : txn.ueId, asn::xnap::ToString(release.cause));
        }
        else
        {
            m_logger->warn("Xn UE context release tx skipped token[%u] ue[%d] reason=peer_not_connected", token,
                           ueId > 0 ? ueId : txn.ueId);
        }

        m_targetHoByToken.erase(tgtIt);
        return;
    }

    if (txn.contextReleaseSent)
        return;

    auto peerIt = m_peers.find(txn.peerClientId);
    if (peerIt == m_peers.end() || peerIt->second.state != EXnPeerState::CONNECTED || !peerIt->second.setupCompleted)
    {
        m_logger->warn("Xn UE context release tx skipped token[%u] ue[%d] reason=peer_not_connected", token,
                       ueId > 0 ? ueId : txn.ueId);
        return;
    }

    asn::xnap::UeContextReleaseFields release{};
    release.oldUeXnapId = txn.oldUeXnapId;
    release.newUeXnapId = txn.newUeXnapId;
    release.cause = asn::xnap::XnapCause::Success;
    sendUeContextRelease(peerIt->second, release, txn.token, 0);
    txn.contextReleaseSent = true;
    m_logger->info("Xn UE context release tx token[%u] ue[%d] cause[%s]", token, ueId > 0 ? ueId : txn.ueId,
                   asn::xnap::ToString(release.cause));
}

void XnTask::onStart()
{
    int nextClientId = 10000;
    for (const auto &cfg : m_base->config->xnNeighbors)
    {
        XnPeerContext peer{};
        peer.clientId = nextClientId++;
        peer.name = cfg.name;
        peer.nci = cfg.nci;
        peer.address = cfg.address;
        peer.port = cfg.port;
        m_peers.emplace(peer.clientId, std::move(peer));
    }

    m_logger->info("Xn peer table initialized peers[%d] local_port[%u]", static_cast<int>(m_peers.size()),
                   m_base->config->xnPort);

    int64_t nowMs = utils::CurrentTimeMillis();
    for (auto &it : m_peers)
        tryConnectPeer(it.second, nowMs);

    setTimer(TIMER_ID_RECONNECT, TIMER_PERIOD_RECONNECT_MS);
}

void XnTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::TIMER_EXPIRED: {
        auto &w = dynamic_cast<NmTimerExpired &>(*msg);
        if (w.timerId == TIMER_ID_RECONNECT)
        {
            setTimer(TIMER_ID_RECONNECT, TIMER_PERIOD_RECONNECT_MS);
            int64_t now = utils::CurrentTimeMillis();
            handleReconnectTick(now);
            handleHoHousekeeping(now);
        }
        break;
    }
    case NtsMessageType::GNB_SCTP: {
        auto &w = dynamic_cast<NmGnbSctp &>(*msg);
        switch (w.present)
        {
        case NmGnbSctp::ASSOCIATION_SETUP:
            handleAssociationSetup(w.clientId, w.associationId, w.inStreams, w.outStreams);
            break;
        case NmGnbSctp::ASSOCIATION_SHUTDOWN:
            handleAssociationShutdown(w.clientId);
            break;
        case NmGnbSctp::RECEIVE_MESSAGE:
            handleReceiveMessage(w.clientId, w.buffer, w.stream);
            break;
        default:
            m_logger->unhandledNts(*msg);
            break;
        }
        break;
    }
    case NtsMessageType::GNB_RLS_TO_NGAP: {
        auto &w = dynamic_cast<NmGnbRlsToNgap &>(*msg);
        switch (w.present)
        {
        case NmGnbRlsToNgap::PRIVATE_DATA_RX:
            handlePrivateMobilityRx(w.ueId, std::move(w.data));
            break;
        default:
            m_logger->unhandledNts(*msg);
            break;
        }
        break;
    }
    default:
        m_logger->unhandledNts(*msg);
        break;
    }
}

std::optional<uint32_t> XnTask::startHandoverPreparation(int ueId, const GnbNeighborConfig &target, std::string &error)
{
    error.clear();

    for (const auto &it : m_sourceHoByToken)
    {
        if (it.second.ueId != ueId)
            continue;
        if (it.second.state != EXnHoTxnState::FAILED && it.second.state != EXnHoTxnState::CANCELED &&
            it.second.state != EXnHoTxnState::CONTEXT_RELEASED)
        {
            error = "Xn handover already in progress for this UE";
            return std::nullopt;
        }
    }

    auto peerClientId = findPeerClientIdForTarget(target);
    if (!peerClientId.has_value())
    {
        error = "No matching Xn peer for target";
        return std::nullopt;
    }

    auto peerIt = m_peers.find(*peerClientId);
    if (peerIt == m_peers.end())
    {
        error = "Internal error: Xn peer context missing";
        return std::nullopt;
    }
    auto &peer = peerIt->second;
    if (peer.state != EXnPeerState::CONNECTED || !peer.setupCompleted)
    {
        error = "Xn peer is not connected or setup-complete";
        return std::nullopt;
    }

    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::InitiatingMessage;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::HandoverPreparation;
    pdu.transactionId = peer.nextTransactionId++;

    XnSourceUeSnapshot ueSnapshot{};
    if (!m_base->ngapTask->getXnSourceUeSnapshot(ueId, ueSnapshot, error))
    {
        error = "Xn source UE snapshot failed: " + error;
        return std::nullopt;
    }

    asn::xnap::HandoverPreparationRequestFields requestFields{};
    requestFields.oldUeXnapId = pdu.transactionId;
    requestFields.ueId = ueId;
    requestFields.sourceNci = m_base->config->nci;
    requestFields.targetNci = target.nci;
    requestFields.cause = asn::xnap::XnapCause::HandoverDesirableForRadioReason;
    requestFields.amfUeNgapId = ueSnapshot.amfUeNgapId;
    requestFields.amfAssociatedId = ueSnapshot.associatedAmfId;
    requestFields.ueAmbrDl = ueSnapshot.ueAmbr.dlAmbr;
    requestFields.ueAmbrUl = ueSnapshot.ueAmbr.ulAmbr;

    for (int psi : ueSnapshot.pduSessionIds)
    {
        auto snapshot = m_base->gtpTask->getSessionSnapshot(ueId, psi);
        if (!snapshot.has_value())
        {
            m_logger->warn("Xn HO prep source session snapshot missing ue[%d] psi[%d]", ueId, psi);
            continue;
        }

        asn::xnap::HandoverPreparationRequestFields::PduSessionItem session{};
        session.psi = static_cast<uint8_t>(snapshot->psi);
        session.sessionType = static_cast<uint8_t>(snapshot->sessionType);
        session.sessionAmbrDl = snapshot->sessionAmbr.dlAmbr;
        session.sessionAmbrUl = snapshot->sessionAmbr.ulAmbr;
        session.ulTeid = snapshot->upTunnel.teid;
        session.ulAddress = snapshot->upTunnel.address.copy();
        session.qfis = snapshot->qfis;
        if (session.qfis.empty())
            session.qfis.push_back(1);

        requestFields.pduSessions.push_back(std::move(session));
    }

    if (requestFields.pduSessions.empty())
    {
        error = "Xn source UE has no transferable PDU sessions";
        return std::nullopt;
    }

    if (!asn::xnap::EncodeHandoverPreparationRequest(requestFields, pdu.payload, error))
    {
        error = "XnAP HO preparation request encode failed: " + error;
        return std::nullopt;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        error = "XnAP encode failed: " + error;
        return std::nullopt;
    }

    sendEncoded(peer.clientId, encoded, 0);

    XnSourceHoTxn txn{};
    txn.token = pdu.transactionId;
    txn.oldUeXnapId = requestFields.oldUeXnapId;
    txn.newUeXnapId = 0;
    txn.ueId = ueId;
    txn.targetName = target.name;
    txn.targetNci = target.nci;
    txn.targetGnbIdLength = target.gnbIdLength;
    txn.targetLinkIp = target.linkIp;
    txn.peerClientId = peer.clientId;
    txn.state = EXnHoTxnState::PREP_SENT;
    txn.snStatusSent = false;
    txn.startedAtMs = utils::CurrentTimeMillis();
    m_sourceHoByToken[txn.token] = txn;

    m_logger->info("Xn HO prep tx ue[%d] token[%u] target[%s] target_nci[0x%016llx]", ueId, txn.token,
                   target.name.c_str(), static_cast<unsigned long long>(target.nci));

    return txn.token;
}

std::optional<uint32_t> XnTask::cancelHandoverPreparation(int ueId, std::string &error)
{
    error.clear();

    XnSourceHoTxn *txn = nullptr;
    for (auto &it : m_sourceHoByToken)
    {
        if (it.second.ueId != ueId)
            continue;
        if (it.second.state == EXnHoTxnState::FAILED || it.second.state == EXnHoTxnState::CANCELED ||
            it.second.state == EXnHoTxnState::CONTEXT_RELEASED)
            continue;
        txn = &it.second;
        break;
    }

    if (txn == nullptr)
    {
        error = "No in-progress Xn handover transaction for this UE";
        return std::nullopt;
    }

    auto peerIt = m_peers.find(txn->peerClientId);
    if (peerIt == m_peers.end())
    {
        error = "Xn peer context missing for transaction";
        return std::nullopt;
    }
    auto &peer = peerIt->second;
    if (peer.state != EXnPeerState::CONNECTED || !peer.setupCompleted)
    {
        error = "Xn peer is not connected or setup-complete";
        return std::nullopt;
    }

    asn::xnap::HandoverCancelFields cancel{};
    cancel.oldUeXnapId = txn->oldUeXnapId;
    cancel.newUeXnapId = txn->newUeXnapId;
    cancel.cause = asn::xnap::XnapCause::Unspecified;
    cancel.detail = "cli_cancel";
    sendHandoverCancel(peer, cancel, txn->token, 0);

    txn->state = EXnHoTxnState::CANCEL_SENT;
    txn->failureReason = "cancel_requested";
    m_logger->info("Xn HO cancel tx ue[%d] token[%u] old_ue_xnap_id[%u] new_ue_xnap_id[%u]", ueId, txn->token,
                   cancel.oldUeXnapId, cancel.newUeXnapId);
    return txn->token;
}

void XnTask::onQuit()
{
    for (const auto &it : m_peers)
    {
        auto closeMsg = std::make_unique<NmGnbSctp>(NmGnbSctp::CONNECTION_CLOSE);
        closeMsg->clientId = it.first;
        m_base->sctpTask->push(std::move(closeMsg));
    }
}

void XnTask::tryConnectPeer(XnPeerContext &peer, int64_t nowMs)
{
    if (peer.state == EXnPeerState::CONNECTED)
        return;
    if (peer.lastConnectAttemptMs != 0 && nowMs - peer.lastConnectAttemptMs < RECONNECT_INTERVAL_MS)
        return;

    peer.lastConnectAttemptMs = nowMs;
    peer.state = EXnPeerState::CONNECTING;

    auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::CONNECTION_REQUEST);
    msg->clientId = peer.clientId;
    msg->localAddress = m_base->config->ngapIp;
    msg->localPort = 0;
    msg->remoteAddress = peer.address;
    msg->remotePort = peer.port;
    msg->ppid = sctp::PayloadProtocolId::NGAP;
    msg->associatedTask = this;
    m_base->sctpTask->push(std::move(msg));

    m_logger->debug("Xn peer connect attempt name[%s] remote[%s:%u]", peer.name.c_str(), peer.address.c_str(),
                    peer.port);
}

void XnTask::handleAssociationSetup(int clientId, int associationId, int inStreams, int outStreams)
{
    auto it = m_peers.find(clientId);
    if (it == m_peers.end())
        return;

    auto &peer = it->second;
    peer.state = EXnPeerState::CONNECTED;
    peer.association.associationId = associationId;
    peer.association.inStreams = inStreams;
    peer.association.outStreams = outStreams;
    peer.setupCompleted = false;

    m_logger->info("Xn peer connected name[%s] remote[%s:%u] ascId[%d]", peer.name.c_str(), peer.address.c_str(),
                   peer.port, associationId);

    sendXnSetupRequest(peer);
}

void XnTask::handleAssociationShutdown(int clientId)
{
    auto it = m_peers.find(clientId);
    if (it == m_peers.end())
        return;

    auto &peer = it->second;
    peer.state = EXnPeerState::NOT_CONNECTED;
    peer.association = {};
    peer.setupCompleted = false;

    auto closeMsg = std::make_unique<NmGnbSctp>(NmGnbSctp::CONNECTION_CLOSE);
    closeMsg->clientId = clientId;
    m_base->sctpTask->push(std::move(closeMsg));

    m_logger->warn("Xn peer disconnected name[%s] remote[%s:%u]", peer.name.c_str(), peer.address.c_str(), peer.port);

    for (auto &it2 : m_sourceHoByToken)
    {
        auto &txn = it2.second;
        if (txn.peerClientId != clientId)
            continue;
        if (txn.state == EXnHoTxnState::FAILED || txn.state == EXnHoTxnState::CANCELED ||
            txn.state == EXnHoTxnState::CONTEXT_RELEASED)
            continue;
        txn.state = EXnHoTxnState::FAILED;
        txn.failureReason = "peer_disconnected";
        m_logger->err("Xn HO prep failed ue[%d] token[%u] reason[%s]", txn.ueId, txn.token,
                      txn.failureReason.c_str());
    }
}

void XnTask::handleReceiveMessage(int clientId, const UniqueBuffer &buffer, uint16_t stream)
{
    auto it = m_peers.find(clientId);
    if (it == m_peers.end())
        return;
    auto &peer = it->second;

    auto encoded = OctetString::FromArray(buffer.data(), buffer.size());
    asn::xnap::XnapPdu pdu{};
    std::string error;
    if (!asn::xnap::Decode(encoded, pdu, error))
    {
        m_logger->warn("Xn peer data rx decode failure name[%s] stream[%u] bytes[%zu] reason[%s]", peer.name.c_str(),
                       stream, buffer.size(), error.c_str());
        return;
    }

    m_logger->info("XnAP rx name[%s] class[%s] procedure[%s] txn[%u] bytes[%zu]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   buffer.size());

    if (pdu.procedureCode == asn::xnap::XnapProcedureCode::XnSetup)
    {
        if (pdu.pduClass == asn::xnap::XnapPduClass::InitiatingMessage)
        {
            asn::xnap::XnSetupRequestFields fields{};
            if (!asn::xnap::DecodeXnSetupRequest(pdu.payload, fields, error))
            {
                m_logger->warn("XnSetupRequest decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }
            sendXnSetupResponse(peer, pdu.transactionId, stream);
            m_logger->info("XnSetup rx name[%s] txn[%u] remote_nci[0x%016llx]", peer.name.c_str(), pdu.transactionId,
                           static_cast<unsigned long long>(fields.localNci));
        }
        else if (pdu.pduClass == asn::xnap::XnapPduClass::SuccessfulOutcome)
        {
            asn::xnap::XnSetupResponseFields fields{};
            if (!asn::xnap::DecodeXnSetupResponse(pdu.payload, fields, error))
            {
                m_logger->warn("XnSetupResponse decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }
            peer.setupCompleted = true;
            m_logger->info("Xn peer setup completed name[%s] txn[%u] remote_nci[0x%016llx]", peer.name.c_str(),
                           pdu.transactionId, static_cast<unsigned long long>(fields.localNci));
        }
        return;
    }

    if (pdu.procedureCode == asn::xnap::XnapProcedureCode::HandoverPreparation)
    {
        if (pdu.pduClass == asn::xnap::XnapPduClass::InitiatingMessage)
        {
            asn::xnap::HandoverPreparationRequestFields request{};
            if (!asn::xnap::DecodeHandoverPreparationRequest(pdu.payload, request, error))
            {
                m_logger->warn("Xn HO prep request decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }

            if (request.ueId <= 0)
            {
                asn::xnap::HandoverPreparationFailureFields failure{};
                failure.oldUeXnapId = request.oldUeXnapId;
                failure.cause = asn::xnap::XnapCause::ProtocolError;
                failure.detail = "invalid_ue_id";
                sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                return;
            }

            if (request.amfUeNgapId < 0)
            {
                asn::xnap::HandoverPreparationFailureFields failure{};
                failure.oldUeXnapId = request.oldUeXnapId;
                failure.cause = asn::xnap::XnapCause::ProtocolError;
                failure.detail = "invalid_amf_ue_ngap_id";
                sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                return;
            }

            if (request.targetNci != m_base->config->nci)
            {
                asn::xnap::HandoverPreparationFailureFields failure{};
                failure.oldUeXnapId = request.oldUeXnapId;
                failure.cause = asn::xnap::XnapCause::UnknownTargetId;
                failure.detail = "target_nci_mismatch";
                sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                return;
            }

            XnTargetPrepContext prepContext{};
            prepContext.token = pdu.transactionId;
            prepContext.amfUeNgapId = request.amfUeNgapId;
            prepContext.sourceAssociatedAmfId = request.amfAssociatedId;
            prepContext.ueAmbr.dlAmbr = request.ueAmbrDl;
            prepContext.ueAmbr.ulAmbr = request.ueAmbrUl;

            std::unordered_set<int> seenPsi{};
            for (const auto &session : request.pduSessions)
            {
                if (session.psi == 0)
                {
                    asn::xnap::HandoverPreparationFailureFields failure{};
                    failure.oldUeXnapId = request.oldUeXnapId;
                    failure.cause = asn::xnap::XnapCause::ProtocolError;
                    failure.detail = "invalid_psi";
                    sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                    return;
                }
                if (seenPsi.count(session.psi))
                {
                    asn::xnap::HandoverPreparationFailureFields failure{};
                    failure.oldUeXnapId = request.oldUeXnapId;
                    failure.cause = asn::xnap::XnapCause::ProtocolError;
                    failure.detail = "duplicate_psi";
                    sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                    return;
                }
                if (!IsValidHoSessionType(session.sessionType))
                {
                    asn::xnap::HandoverPreparationFailureFields failure{};
                    failure.oldUeXnapId = request.oldUeXnapId;
                    failure.cause = asn::xnap::XnapCause::NoRadioResourcesAvailable;
                    failure.detail = "unsupported_session_type";
                    sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                    return;
                }
                if (session.ulTeid == 0 || !IsValidTnlAddressLength(session.ulAddress.length()))
                {
                    asn::xnap::HandoverPreparationFailureFields failure{};
                    failure.oldUeXnapId = request.oldUeXnapId;
                    failure.cause = asn::xnap::XnapCause::ProtocolError;
                    failure.detail = "invalid_ul_tnl";
                    sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                    return;
                }
                if (session.qfis.empty())
                {
                    asn::xnap::HandoverPreparationFailureFields failure{};
                    failure.oldUeXnapId = request.oldUeXnapId;
                    failure.cause = asn::xnap::XnapCause::ProtocolError;
                    failure.detail = "empty_qfi_list";
                    sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                    return;
                }
                for (auto qfi : session.qfis)
                {
                    if (!IsValidQfi(qfi))
                    {
                        asn::xnap::HandoverPreparationFailureFields failure{};
                        failure.oldUeXnapId = request.oldUeXnapId;
                        failure.cause = asn::xnap::XnapCause::ProtocolError;
                        failure.detail = "invalid_qfi";
                        sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                        return;
                    }
                }

                XnTargetPduSnapshot targetSession{};
                targetSession.psi = static_cast<int>(session.psi);
                targetSession.sessionType = static_cast<PduSessionType>(session.sessionType);
                targetSession.sessionAmbr.dlAmbr = session.sessionAmbrDl;
                targetSession.sessionAmbr.ulAmbr = session.sessionAmbrUl;
                targetSession.upTunnel.teid = session.ulTeid;
                targetSession.upTunnel.address = session.ulAddress.copy();
                targetSession.qfis = session.qfis;
                prepContext.pduSessions.push_back(std::move(targetSession));
                seenPsi.insert(session.psi);
            }

            if (prepContext.pduSessions.empty())
            {
                asn::xnap::HandoverPreparationFailureFields failure{};
                failure.oldUeXnapId = request.oldUeXnapId;
                failure.cause = asn::xnap::XnapCause::NoRadioResourcesAvailable;
                failure.detail = "empty_pdu_list";
                sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                return;
            }

            std::string prepError;
            if (!m_base->ngapTask->prepareXnTargetHandover(prepContext, prepError))
            {
                asn::xnap::HandoverPreparationFailureFields failure{};
                failure.oldUeXnapId = request.oldUeXnapId;
                if (prepError.rfind("invalid_", 0) == 0 || prepError.rfind("duplicate_", 0) == 0)
                    failure.cause = asn::xnap::XnapCause::ProtocolError;
                else
                    failure.cause = asn::xnap::XnapCause::NoRadioResourcesAvailable;
                failure.detail = "ngap_prep_failed:" + prepError;
                sendHandoverPreparationFailure(peer, failure, pdu.transactionId, stream);
                return;
            }

            uint32_t newUeXnapId = m_newUeXnapIdCounter++;
            XnTargetHoTxn targetTxn{};
            targetTxn.token = pdu.transactionId;
            targetTxn.oldUeXnapId = request.oldUeXnapId;
            targetTxn.newUeXnapId = newUeXnapId;
            targetTxn.peerClientId = clientId;
            targetTxn.ueId = request.ueId;
            targetTxn.sourceNci = request.sourceNci;
            targetTxn.receivedAtMs = utils::CurrentTimeMillis();
            m_targetHoByToken[targetTxn.token] = targetTxn;

            asn::xnap::HandoverPreparationAcknowledgeFields ack{};
            ack.oldUeXnapId = request.oldUeXnapId;
            ack.newUeXnapId = newUeXnapId;
            ack.admittedPduCount = static_cast<uint8_t>(prepContext.pduSessions.size());
            ack.failedPduCount = 0;
            sendHandoverPreparationAcknowledge(peer, ack, pdu.transactionId, stream);
            m_logger->info("Xn HO prep rx token[%u] ue[%d] old_ue_xnap_id[%u] new_ue_xnap_id[%u] source_nci[0x%016llx] "
                           "cause[%s] result[ack]",
                           pdu.transactionId, request.ueId, request.oldUeXnapId, newUeXnapId,
                           static_cast<unsigned long long>(request.sourceNci), asn::xnap::ToString(request.cause));
            return;
        }

        if (pdu.pduClass == asn::xnap::XnapPduClass::SuccessfulOutcome)
        {
            asn::xnap::HandoverPreparationAcknowledgeFields ack{};
            if (!asn::xnap::DecodeHandoverPreparationAcknowledge(pdu.payload, ack, error))
            {
                m_logger->warn("Xn HO prep acknowledge decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }

            auto srcIt = m_sourceHoByToken.find(pdu.transactionId);
            if (srcIt != m_sourceHoByToken.end())
            {
                if (srcIt->second.state == EXnHoTxnState::CANCEL_SENT || srcIt->second.state == EXnHoTxnState::CANCELED ||
                    srcIt->second.state == EXnHoTxnState::FAILED ||
                    srcIt->second.state == EXnHoTxnState::CONTEXT_RELEASED)
                {
                    m_logger->warn("Xn HO prep ack rx ignored ue[%d] token[%u] state[%d]", srcIt->second.ueId,
                                   srcIt->second.token, static_cast<int>(srcIt->second.state));
                    return;
                }

                srcIt->second.oldUeXnapId = ack.oldUeXnapId;
                srcIt->second.newUeXnapId = ack.newUeXnapId;
                srcIt->second.state = EXnHoTxnState::ACK_RECEIVED;
                m_logger->info("Xn HO prep ack rx ue[%d] token[%u] old_ue_xnap_id[%u] new_ue_xnap_id[%u] admitted[%u] "
                               "failed[%u]",
                               srcIt->second.ueId, srcIt->second.token, ack.oldUeXnapId, ack.newUeXnapId,
                               ack.admittedPduCount, ack.failedPduCount);

                asn::xnap::SnStatusTransferFields sn{};
                sn.oldUeXnapId = ack.oldUeXnapId;
                sn.newUeXnapId = ack.newUeXnapId;
                sn.drbCount = ack.admittedPduCount;
                sendSnStatusTransfer(peer, sn, pdu.transactionId, stream);
                srcIt->second.state = EXnHoTxnState::SN_STATUS_SENT;
                srcIt->second.snStatusSent = true;

                if (!triggerUeMoveExecution(srcIt->second))
                {
                    srcIt->second.state = EXnHoTxnState::FAILED;
                    srcIt->second.failureReason = "ue_move_trigger_failed";
                    m_logger->err("Xn HO move trigger failed ue[%d] token[%u]", srcIt->second.ueId, srcIt->second.token);
                }
            }
            else
            {
                m_logger->warn("Xn HO prep ack rx token[%u] without matching source transaction", pdu.transactionId);
            }
            return;
        }

        if (pdu.pduClass == asn::xnap::XnapPduClass::UnsuccessfulOutcome)
        {
            asn::xnap::HandoverPreparationFailureFields failure{};
            if (!asn::xnap::DecodeHandoverPreparationFailure(pdu.payload, failure, error))
            {
                m_logger->warn("Xn HO prep failure decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }

            auto srcIt = m_sourceHoByToken.find(pdu.transactionId);
            if (srcIt != m_sourceHoByToken.end())
            {
                if (srcIt->second.state == EXnHoTxnState::CANCEL_SENT || srcIt->second.state == EXnHoTxnState::CANCELED)
                {
                    m_logger->debug("Xn HO prep fail rx ignored ue[%d] token[%u] reason=cancel_in_progress",
                                    srcIt->second.ueId, srcIt->second.token);
                    return;
                }

                srcIt->second.state = EXnHoTxnState::FAILED;
                srcIt->second.oldUeXnapId = failure.oldUeXnapId;
                srcIt->second.failureReason =
                    std::string(asn::xnap::ToString(failure.cause)) + ":" + failure.detail;
                m_logger->err("Xn HO prep fail rx ue[%d] token[%u] old_ue_xnap_id[%u] cause[%s] detail[%s]",
                              srcIt->second.ueId, srcIt->second.token, failure.oldUeXnapId,
                              asn::xnap::ToString(failure.cause), failure.detail.c_str());
            }
            else
            {
                m_logger->warn("Xn HO prep fail rx token[%u] without matching source transaction", pdu.transactionId);
            }
            return;
        }
    }

    if (pdu.procedureCode == asn::xnap::XnapProcedureCode::SnStatusTransfer &&
        pdu.pduClass == asn::xnap::XnapPduClass::InitiatingMessage)
    {
        asn::xnap::SnStatusTransferFields sn{};
        if (!asn::xnap::DecodeSnStatusTransfer(pdu.payload, sn, error))
        {
            m_logger->warn("Xn SN status transfer decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                           pdu.transactionId, error.c_str());
            return;
        }

        auto tgtIt = m_targetHoByToken.find(pdu.transactionId);
        if (tgtIt != m_targetHoByToken.end())
        {
            tgtIt->second.snStatusReceived = true;
            m_logger->info("Xn SN status transfer rx token[%u] old_ue_xnap_id[%u] new_ue_xnap_id[%u] drb_count[%u]",
                           pdu.transactionId, sn.oldUeXnapId, sn.newUeXnapId, sn.drbCount);
        }
        else
        {
            m_logger->warn("Xn SN status transfer rx token[%u] without matching target transaction", pdu.transactionId);
        }
        return;
    }

    if (pdu.procedureCode == asn::xnap::XnapProcedureCode::UeContextRelease &&
        pdu.pduClass == asn::xnap::XnapPduClass::InitiatingMessage)
    {
        asn::xnap::UeContextReleaseFields release{};
        if (!asn::xnap::DecodeUeContextRelease(pdu.payload, release, error))
        {
            m_logger->warn("Xn UE context release decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                           pdu.transactionId, error.c_str());
            return;
        }

        auto srcIt = m_sourceHoByToken.find(pdu.transactionId);
        if (srcIt != m_sourceHoByToken.end())
        {
            srcIt->second.state = EXnHoTxnState::CONTEXT_RELEASED;
            srcIt->second.failureReason = std::string("release:") + asn::xnap::ToString(release.cause);
            m_logger->info("Xn UE context release rx token[%u] ue[%d] cause[%s]", pdu.transactionId,
                           srcIt->second.ueId, asn::xnap::ToString(release.cause));

            bool isSuccess = (release.cause == asn::xnap::XnapCause::Success);
            m_base->ngapTask->requestContextReleaseForXnHandover(srcIt->second.ueId, isSuccess);
        }
        else
        {
            m_logger->warn("Xn UE context release rx token[%u] without matching source transaction", pdu.transactionId);
        }
        return;
    }

    if (pdu.procedureCode == asn::xnap::XnapProcedureCode::HandoverCancel)
    {
        if (pdu.pduClass == asn::xnap::XnapPduClass::InitiatingMessage)
        {
            asn::xnap::HandoverCancelFields cancel{};
            if (!asn::xnap::DecodeHandoverCancel(pdu.payload, cancel, error))
            {
                m_logger->warn("Xn HO cancel decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }

            auto tgtIt = m_targetHoByToken.find(pdu.transactionId);
            if (tgtIt != m_targetHoByToken.end())
            {
                m_logger->info("Xn HO cancel rx token[%u] old_ue_xnap_id[%u] new_ue_xnap_id[%u] cause[%s] detail[%s]",
                               pdu.transactionId, cancel.oldUeXnapId, cancel.newUeXnapId,
                               asn::xnap::ToString(cancel.cause), cancel.detail.c_str());
                m_targetHoByToken.erase(tgtIt);
            }
            else
            {
                m_logger->warn("Xn HO cancel rx token[%u] without matching target transaction", pdu.transactionId);
            }

            asn::xnap::HandoverCancelAcknowledgeFields ack{};
            ack.oldUeXnapId = cancel.oldUeXnapId;
            ack.newUeXnapId = cancel.newUeXnapId;
            sendHandoverCancelAcknowledge(peer, ack, pdu.transactionId, stream);
            return;
        }

        if (pdu.pduClass == asn::xnap::XnapPduClass::SuccessfulOutcome)
        {
            asn::xnap::HandoverCancelAcknowledgeFields ack{};
            if (!asn::xnap::DecodeHandoverCancelAcknowledge(pdu.payload, ack, error))
            {
                m_logger->warn("Xn HO cancel ack decode failure name[%s] txn[%u] reason[%s]", peer.name.c_str(),
                               pdu.transactionId, error.c_str());
                return;
            }

            auto srcIt = m_sourceHoByToken.find(pdu.transactionId);
            if (srcIt != m_sourceHoByToken.end())
            {
                srcIt->second.oldUeXnapId = ack.oldUeXnapId;
                srcIt->second.newUeXnapId = ack.newUeXnapId;
                srcIt->second.state = EXnHoTxnState::CANCELED;
                srcIt->second.failureReason = "cancel_ack";
                m_logger->info("Xn HO cancel ack rx ue[%d] token[%u] old_ue_xnap_id[%u] new_ue_xnap_id[%u]",
                               srcIt->second.ueId, srcIt->second.token, ack.oldUeXnapId, ack.newUeXnapId);
            }
            else
            {
                m_logger->warn("Xn HO cancel ack rx token[%u] without matching source transaction", pdu.transactionId);
            }
            return;
        }
    }
}

bool XnTask::triggerUeMoveExecution(XnSourceHoTxn &txn)
{
    rls::ho1::Message cmd{};
    cmd.msgType = rls::ho1::MsgType::HO_CMD;
    cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::token, OctetString::FromOctet4(txn.token)});

    int targetCellId = CellIdFromNci(txn.targetNci, txn.targetGnbIdLength);
    if (targetCellId > 0)
        cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::target_cell_id, OctetString::FromOctet4(targetCellId)});

    cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::target_nci, OctetString::FromOctet8(txn.targetNci)});

    if (txn.targetLinkIp.has_value())
        cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::target_link_ip, OctetString::FromAscii(*txn.targetLinkIp)});

    uint64_t ueSti = m_base->rlsTask->getStiForUeId(txn.ueId);
    if (ueSti != 0)
        cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::ue_sti, OctetString::FromOctet8(ueSti)});

    cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::rrc_defer, OctetString::FromOctet4(1)});

    auto priv = std::make_unique<NmGnbNgapToRls>(NmGnbNgapToRls::PRIVATE_DATA_TX);
    priv->ueId = txn.ueId;
    priv->data = rls::ho1::Encode(cmd);
    m_base->rlsTask->push(std::move(priv));

    OctetString reconfig = BuildRrcReconfigurationForHandover(txn.ueId, txn.targetNci);
    if (reconfig.length() == 0)
    {
        m_logger->err("Xn HO move trigger failed ue[%d] token[%u] reason[rrc_reconfig_encode]", txn.ueId, txn.token);
        return false;
    }

    auto w = std::make_unique<NmGnbNgapToRrc>(NmGnbNgapToRrc::HO_COMMAND);
    w->ueId = txn.ueId;
    w->rrcReconfiguration = std::move(reconfig);
    m_base->rrcTask->push(std::move(w));

    m_logger->info("Xn HO move trigger tx ue[%d] token[%u] target_nci[0x%016llx] target_link_ip[%s]", txn.ueId,
                   txn.token, static_cast<unsigned long long>(txn.targetNci),
                   txn.targetLinkIp.has_value() ? txn.targetLinkIp->c_str() : "n/a");
    return true;
}

void XnTask::handlePrivateMobilityRx(int ueId, OctetString &&payload)
{
    if (!rls::ho1::LooksLikeHo1(payload))
        return;

    auto decoded = rls::ho1::Decode(payload);
    if (!decoded.ok)
        return;

    auto tokenBytes = rls::ho1::FindTlvBytes(decoded.message, rls::ho1::tlv::token);
    if (!tokenBytes.has_value())
        return;

    auto tokenOpt = Ho1TokenToU32(*tokenBytes);
    if (!tokenOpt.has_value())
        return;
    uint32_t token = *tokenOpt;

    if (decoded.message.msgType == rls::ho1::MsgType::HO_COMPLETE)
    {
        auto tgtIt = m_targetHoByToken.find(token);
        if (tgtIt == m_targetHoByToken.end())
            return;

        auto &txn = tgtIt->second;
        if (!txn.completeReceived)
        {
            txn.completeReceived = true;
            if (txn.ueId == 0)
                txn.ueId = ueId;
            m_logger->info("Xn HO complete rx ue[%d] token[%u] old_ue_xnap_id[%u] new_ue_xnap_id[%u]", ueId, token,
                           txn.oldUeXnapId, txn.newUeXnapId);
        }
        else
        {
            m_logger->debug("Xn HO complete rx duplicate ue[%d] token[%u]", ueId, token);
        }
        m_logger->debug("Xn HO complete rx token[%u] ue[%d] action[wait_path_switch]", token, ueId);
        return;
    }

    if (decoded.message.msgType != rls::ho1::MsgType::HO_FAIL)
        return;

    auto reasonCode = rls::ho1::FindTlvU32(decoded.message, rls::ho1::tlv::reason_code);
    auto reasonDetail = rls::ho1::FindTlvUtf8(decoded.message, rls::ho1::tlv::reason_detail);
    uint32_t reasonCodeVal = reasonCode.value_or(0);
    std::string reasonDetailStr = reasonDetail.value_or("n/a");

    auto srcIt = m_sourceHoByToken.find(token);
    if (srcIt != m_sourceHoByToken.end())
    {
        auto &txn = srcIt->second;
        txn.failureReason = "ue_fail:" + std::to_string(reasonCodeVal) + ":" + reasonDetailStr;

        auto peerIt = m_peers.find(txn.peerClientId);
        if (peerIt != m_peers.end() && peerIt->second.state == EXnPeerState::CONNECTED && peerIt->second.setupCompleted)
        {
            asn::xnap::HandoverCancelFields cancel{};
            cancel.oldUeXnapId = txn.oldUeXnapId;
            cancel.newUeXnapId = txn.newUeXnapId;
            cancel.cause = asn::xnap::XnapCause::Unspecified;
            cancel.detail = txn.failureReason;
            sendHandoverCancel(peerIt->second, cancel, txn.token, 0);
            txn.state = EXnHoTxnState::CANCEL_SENT;
        }
        else
        {
            txn.state = EXnHoTxnState::FAILED;
        }

        m_logger->err("Xn HO fail rx source ue[%d] token[%u] reason_code[%u] detail[%s]", ueId, token, reasonCodeVal,
                      reasonDetailStr.c_str());
        return;
    }

    auto tgtIt = m_targetHoByToken.find(token);
    if (tgtIt != m_targetHoByToken.end())
    {
        m_logger->err("Xn HO fail rx target ue[%d] token[%u] reason_code[%u] detail[%s]", ueId, token, reasonCodeVal,
                      reasonDetailStr.c_str());
        m_targetHoByToken.erase(tgtIt);
    }
}

void XnTask::sendXnSetupRequest(XnPeerContext &peer)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::InitiatingMessage;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::XnSetup;
    pdu.transactionId = peer.nextTransactionId++;

    asn::xnap::XnSetupRequestFields requestFields{};
    requestFields.localNci = m_base->config->nci;

    std::string error;
    if (!asn::xnap::EncodeXnSetupRequest(requestFields, pdu.payload, error))
    {
        m_logger->err("XnAP XnSetupRequest payload encode failure name[%s] reason[%s]", peer.name.c_str(),
                      error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, 0);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendXnSetupResponse(XnPeerContext &peer, uint32_t transactionId, uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::SuccessfulOutcome;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::XnSetup;
    pdu.transactionId = transactionId;

    asn::xnap::XnSetupResponseFields responseFields{};
    responseFields.localNci = m_base->config->nci;

    std::string error;
    if (!asn::xnap::EncodeXnSetupResponse(responseFields, pdu.payload, error))
    {
        m_logger->err("XnAP XnSetupResponse payload encode failure name[%s] reason[%s]", peer.name.c_str(),
                      error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendSnStatusTransfer(XnPeerContext &peer, const asn::xnap::SnStatusTransferFields &fields,
                                  uint32_t transactionId, uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::InitiatingMessage;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::SnStatusTransfer;
    pdu.transactionId = transactionId;

    std::string error;
    if (!asn::xnap::EncodeSnStatusTransfer(fields, pdu.payload, error))
    {
        m_logger->err("XnAP SN status payload encode failure name[%s] reason[%s]", peer.name.c_str(), error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendUeContextRelease(XnPeerContext &peer, const asn::xnap::UeContextReleaseFields &fields,
                                  uint32_t transactionId, uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::InitiatingMessage;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::UeContextRelease;
    pdu.transactionId = transactionId;

    std::string error;
    if (!asn::xnap::EncodeUeContextRelease(fields, pdu.payload, error))
    {
        m_logger->err("XnAP UE context release payload encode failure name[%s] reason[%s]", peer.name.c_str(),
                      error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendHandoverPreparationFailure(XnPeerContext &peer, const asn::xnap::HandoverPreparationFailureFields &fields,
                                            uint32_t transactionId, uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::UnsuccessfulOutcome;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::HandoverPreparation;
    pdu.transactionId = transactionId;
    std::string error;
    if (!asn::xnap::EncodeHandoverPreparationFailure(fields, pdu.payload, error))
    {
        m_logger->err("XnAP HandoverPreparationFailure payload encode failure name[%s] reason[%s]",
                      peer.name.c_str(), error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendHandoverPreparationAcknowledge(
    XnPeerContext &peer, const asn::xnap::HandoverPreparationAcknowledgeFields &fields, uint32_t transactionId,
    uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::SuccessfulOutcome;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::HandoverPreparation;
    pdu.transactionId = transactionId;
    std::string error;
    if (!asn::xnap::EncodeHandoverPreparationAcknowledge(fields, pdu.payload, error))
    {
        m_logger->err("XnAP HandoverPreparationAcknowledge payload encode failure name[%s] reason[%s]",
                      peer.name.c_str(), error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendHandoverCancel(XnPeerContext &peer, const asn::xnap::HandoverCancelFields &fields,
                                uint32_t transactionId, uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::InitiatingMessage;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::HandoverCancel;
    pdu.transactionId = transactionId;

    std::string error;
    if (!asn::xnap::EncodeHandoverCancel(fields, pdu.payload, error))
    {
        m_logger->err("XnAP HandoverCancel payload encode failure name[%s] reason[%s]", peer.name.c_str(),
                      error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendHandoverCancelAcknowledge(XnPeerContext &peer,
                                           const asn::xnap::HandoverCancelAcknowledgeFields &fields,
                                           uint32_t transactionId, uint16_t stream)
{
    asn::xnap::XnapPdu pdu{};
    pdu.pduClass = asn::xnap::XnapPduClass::SuccessfulOutcome;
    pdu.procedureCode = asn::xnap::XnapProcedureCode::HandoverCancel;
    pdu.transactionId = transactionId;

    std::string error;
    if (!asn::xnap::EncodeHandoverCancelAcknowledge(fields, pdu.payload, error))
    {
        m_logger->err("XnAP HandoverCancelAcknowledge payload encode failure name[%s] reason[%s]", peer.name.c_str(),
                      error.c_str());
        return;
    }

    OctetString encoded;
    if (!asn::xnap::Encode(pdu, encoded, error))
    {
        m_logger->err("XnAP tx encode failure name[%s] procedure[%s] reason[%s]", peer.name.c_str(),
                      asn::xnap::ToString(pdu.procedureCode), error.c_str());
        return;
    }

    sendEncoded(peer.clientId, encoded, stream);
    m_logger->info("XnAP tx name[%s] class[%s] procedure[%s] txn[%u] bytes[%d]", peer.name.c_str(),
                   asn::xnap::ToString(pdu.pduClass), asn::xnap::ToString(pdu.procedureCode), pdu.transactionId,
                   encoded.length());
}

void XnTask::sendEncoded(int clientId, const OctetString &encoded, uint16_t stream)
{
    auto *copy = new uint8_t[encoded.length()];
    std::memcpy(copy, encoded.data(), static_cast<size_t>(encoded.length()));

    auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::SEND_MESSAGE);
    msg->clientId = clientId;
    msg->stream = stream;
    msg->buffer = UniqueBuffer{copy, static_cast<size_t>(encoded.length())};
    m_base->sctpTask->push(std::move(msg));
}

void XnTask::handleReconnectTick(int64_t nowMs)
{
    for (auto &it : m_peers)
        tryConnectPeer(it.second, nowMs);
}

void XnTask::handleHoHousekeeping(int64_t nowMs)
{
    const int64_t prepTimeout = m_base->config->ngapTimers.tngRelocPrepMs;
    const int64_t doneTtl = m_base->config->ngapTimers.tngRelocOverallMs;
    const int64_t targetTtl = m_base->config->ngapTimers.preparedTtlMs;

    std::vector<uint32_t> sourceErase;
    for (auto &it : m_sourceHoByToken)
    {
        auto &txn = it.second;
        if (txn.state == EXnHoTxnState::PREP_SENT)
        {
            if (nowMs - txn.startedAtMs > prepTimeout)
            {
                auto peerIt = m_peers.find(txn.peerClientId);
                if (peerIt != m_peers.end() && peerIt->second.state == EXnPeerState::CONNECTED &&
                    peerIt->second.setupCompleted)
                {
                    asn::xnap::HandoverCancelFields cancel{};
                    cancel.oldUeXnapId = txn.oldUeXnapId;
                    cancel.newUeXnapId = txn.newUeXnapId;
                    cancel.cause = asn::xnap::XnapCause::Unspecified;
                    cancel.detail = "txnrelocprep_expiry";
                    sendHandoverCancel(peerIt->second, cancel, txn.token, 0);
                    txn.state = EXnHoTxnState::CANCEL_SENT;
                    txn.failureReason = "txnrelocprep_expiry:cancel_sent";
                    m_logger->err("Xn HO prep timer expiry ue[%d] token[%u] timer[TXnRELOCprep] action[send_cancel]",
                                  txn.ueId, txn.token);
                }
                else
                {
                    txn.state = EXnHoTxnState::FAILED;
                    txn.failureReason = "txnrelocprep_expiry:peer_not_connected";
                    m_logger->err("Xn HO prep timer expiry ue[%d] token[%u] timer[TXnRELOCprep] action[mark_failed]",
                                  txn.ueId, txn.token);
                }
            }
            continue;
        }

        if ((txn.state == EXnHoTxnState::ACK_RECEIVED || txn.state == EXnHoTxnState::SN_STATUS_SENT ||
             txn.state == EXnHoTxnState::CANCEL_SENT) &&
            nowMs - txn.startedAtMs > doneTtl)
        {
            auto prevState = txn.state;
            txn.state = EXnHoTxnState::FAILED;
            txn.failureReason = "txnrelocoverall_expiry";
            m_logger->err("Xn HO overall timer expiry ue[%d] token[%u] timer[TXnRELOCoverall] state[%d]", txn.ueId,
                          txn.token, static_cast<int>(prevState));
            m_base->ngapTask->requestContextReleaseForXnHandover(txn.ueId, false);
        }

        if (txn.state == EXnHoTxnState::FAILED || txn.state == EXnHoTxnState::CANCELED ||
            txn.state == EXnHoTxnState::CONTEXT_RELEASED || nowMs - txn.startedAtMs > doneTtl)
            sourceErase.push_back(txn.token);
    }
    for (auto token : sourceErase)
        m_sourceHoByToken.erase(token);

    std::vector<uint32_t> targetErase;
    for (auto &it : m_targetHoByToken)
    {
        if (nowMs - it.second.receivedAtMs > targetTtl)
        {
            auto peerIt = m_peers.find(it.second.peerClientId);
            if (!it.second.contextReleaseSent && peerIt != m_peers.end() && peerIt->second.state == EXnPeerState::CONNECTED &&
                peerIt->second.setupCompleted)
            {
                asn::xnap::UeContextReleaseFields release{};
                release.oldUeXnapId = it.second.oldUeXnapId;
                release.newUeXnapId = it.second.newUeXnapId;
                release.cause = asn::xnap::XnapCause::Unspecified;
                sendUeContextRelease(peerIt->second, release, it.second.token, 0);
                it.second.contextReleaseSent = true;
            }
            m_logger->warn("Xn HO target ttl expiry token[%u] ue[%d] complete_rx[%s] timer[prepared_ttl]",
                           it.second.token, it.second.ueId, it.second.completeReceived ? "true" : "false");
            targetErase.push_back(it.first);
        }
    }
    for (auto token : targetErase)
        m_targetHoByToken.erase(token);
}

std::optional<int> XnTask::findPeerClientIdForTarget(const GnbNeighborConfig &target) const
{
    for (const auto &it : m_peers)
    {
        if (matchesTarget(it.second, target))
            return it.first;
    }
    return std::nullopt;
}

bool XnTask::matchesTarget(const XnPeerContext &peer, const GnbNeighborConfig &target) const
{
    if (peer.nci.has_value() && peer.nci.value() == target.nci)
        return true;
    return peer.name == target.name;
}

bool XnTask::isPeerConfiguredForTarget(const GnbNeighborConfig &target) const
{
    for (const auto &it : m_peers)
    {
        if (matchesTarget(it.second, target))
            return true;
    }
    return false;
}

bool XnTask::isPeerConnectedForTarget(const GnbNeighborConfig &target) const
{
    for (const auto &it : m_peers)
    {
        if (matchesTarget(it.second, target) && it.second.state == EXnPeerState::CONNECTED && it.second.setupCompleted)
            return true;
    }
    return false;
}

Json ToJson(const EXnPeerState &v)
{
    switch (v)
    {
    case EXnPeerState::NOT_CONNECTED:
        return "NOT_CONNECTED";
    case EXnPeerState::CONNECTING:
        return "CONNECTING";
    case EXnPeerState::CONNECTED:
        return "CONNECTED";
    default:
        return "?";
    }
}

Json ToJson(const EXnHoTxnState &v)
{
    switch (v)
    {
    case EXnHoTxnState::PREP_SENT:
        return "PREP_SENT";
    case EXnHoTxnState::ACK_RECEIVED:
        return "ACK_RECEIVED";
    case EXnHoTxnState::SN_STATUS_SENT:
        return "SN_STATUS_SENT";
    case EXnHoTxnState::CANCEL_SENT:
        return "CANCEL_SENT";
    case EXnHoTxnState::CONTEXT_RELEASED:
        return "CONTEXT_RELEASED";
    case EXnHoTxnState::CANCELED:
        return "CANCELED";
    case EXnHoTxnState::FAILED:
        return "FAILED";
    default:
        return "?";
    }
}

} // namespace nr::gnb
