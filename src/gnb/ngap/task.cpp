//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <sstream>

#include <gnb/app/task.hpp>
#include <gnb/sctp/task.hpp>
#include <utils/common.hpp>

namespace nr::gnb
{

NgapTask::NgapTask(TaskBase *base) : m_base{base}, m_ueNgapIdCounter{}, m_downlinkTeidCounter{}, m_isInitialized{}
{
    m_logger = base->logBase->makeUniqueLogger("ngap");
}

void NgapTask::onStart()
{
    for (auto &amfConfig : m_base->config->amfConfigs)
        createAmfContext(amfConfig);
    if (m_amfCtx.empty())
        m_logger->warn("No AMF configuration is provided");

    for (auto &amfCtx : m_amfCtx)
    {
        auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::CONNECTION_REQUEST);
        msg->clientId = amfCtx.second->ctxId;
        msg->localAddress = m_base->config->ngapIp;
        msg->localPort = 0;
        msg->remoteAddress = amfCtx.second->address;
        msg->remotePort = amfCtx.second->port;
        msg->ppid = sctp::PayloadProtocolId::NGAP;
        msg->associatedTask = this;
        m_base->sctpTask->push(std::move(msg));
    }
}

void NgapTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::GNB_RRC_TO_NGAP: {
        auto &w = dynamic_cast<NmGnbRrcToNgap &>(*msg);
        switch (w.present)
        {
        case NmGnbRrcToNgap::INITIAL_NAS_DELIVERY: {
            handleInitialNasTransport(w.ueId, w.pdu, w.rrcEstablishmentCause, w.sTmsi);
            break;
        }
        case NmGnbRrcToNgap::UPLINK_NAS_DELIVERY: {
            handleUplinkNasTransport(w.ueId, w.pdu);
            break;
        }
        case NmGnbRrcToNgap::RADIO_LINK_FAILURE: {
            handleRadioLinkFailure(w.ueId);
            break;
        }
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
        case NmGnbSctp::RECEIVE_MESSAGE:
            handleSctpMessage(w.clientId, w.stream, w.buffer);
            break;
        case NmGnbSctp::ASSOCIATION_SHUTDOWN:
            handleAssociationShutdown(w.clientId);
            break;
        default:
            m_logger->unhandledNts(*msg);
            break;
        }
        break;
    }
    default: {
        m_logger->unhandledNts(*msg);
        break;
    }
    }
}

void NgapTask::onQuit()
{
    for (auto &i : m_ueCtx)
        delete i.second;
    for (auto &i : m_amfCtx)
        delete i.second;
    m_ueCtx.clear();
    m_amfCtx.clear();
}

void NgapTask::rememberPagingHint(const GutiMobileIdentity &sTmsi, int amfId)
{
    FiveGSTmsiKey key{sTmsi.amfSetId, sTmsi.amfPointer, static_cast<uint32_t>(sTmsi.tmsi)};
    m_pagingAmfHints[key] = PagingAmfHint{amfId, utils::CurrentTimeMillis()};
}

std::optional<int> NgapTask::findPagingHint(const GutiMobileIdentity &sTmsi)
{
    static constexpr int64_t TTL_MS = 10 * 60 * 1000; // 10 minutes

    FiveGSTmsiKey key{sTmsi.amfSetId, sTmsi.amfPointer, static_cast<uint32_t>(sTmsi.tmsi)};
    auto it = m_pagingAmfHints.find(key);
    if (it == m_pagingAmfHints.end())
        return std::nullopt;

    int64_t now = utils::CurrentTimeMillis();
    if (now - it->second.lastSeenMs > TTL_MS)
    {
        m_pagingAmfHints.erase(it);
        return std::nullopt;
    }

    return it->second.amfCtxId;
}

void NgapTask::requestAmfConnectionIfNeeded(int amfId)
{
    auto *amf = findAmfContext(amfId);
    if (!amf)
        return;

    if (amf->state != EAmfState::NOT_CONNECTED)
        return;

    m_logger->warn("Requesting SCTP connection to AMF[%d] (state NOT_CONNECTED)", amfId);

    auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::CONNECTION_REQUEST);
    msg->clientId = amf->ctxId;
    msg->localAddress = m_base->config->ngapIp;
    msg->localPort = 0;
    msg->remoteAddress = amf->address;
    msg->remotePort = amf->port;
    msg->ppid = sctp::PayloadProtocolId::NGAP;
    msg->associatedTask = this;
    m_base->sctpTask->push(std::move(msg));
}

} // namespace nr::gnb
