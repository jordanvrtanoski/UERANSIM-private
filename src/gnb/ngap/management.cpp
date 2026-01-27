//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <utils/common.hpp>

namespace nr::gnb
{

static const char *ToString(EAmfState state)
{
    switch (state)
    {
    case EAmfState::NOT_CONNECTED:
        return "NOT_CONNECTED";
    case EAmfState::WAITING_NG_SETUP:
        return "WAITING_NG_SETUP";
    case EAmfState::CONNECTED:
        return "CONNECTED";
    }
    return "UNKNOWN";
}

static std::string DumpSupportedSsts(const NgapAmfContext &amf)
{
    std::string s;
    bool first = true;
    for (const auto *plmnSupport : amf.plmnSupportList)
    {
        for (const auto &slice : plmnSupport->sliceSupportList.slices)
        {
            if (!first)
                s += ",";
            first = false;
            s += std::to_string(static_cast<int>(slice.sst));
        }
    }
    return first ? std::string{"<none>"} : s;
}

NgapAmfContext *NgapTask::findAmfContext(int ctxId)
{
    NgapAmfContext *ctx = nullptr;
    if (m_amfCtx.count(ctxId))
        ctx = m_amfCtx[ctxId];
    if (ctx == nullptr)
        m_logger->err("AMF context not found with id: %d", ctxId);
    return ctx;
}

void NgapTask::createAmfContext(const GnbAmfConfig &conf)
{
    auto *ctx = new NgapAmfContext();
    ctx->ctxId = utils::NextId();
    ctx->state = EAmfState::NOT_CONNECTED;
    ctx->address = conf.address;
    ctx->port = conf.port;
    m_amfCtx[ctx->ctxId] = ctx;
}

void NgapTask::createUeContext(int ueId, int32_t &requestedSliceType, std::optional<NetworkSlice> requestedNssai,
                               const std::optional<GutiMobileIdentity> &sTmsi)
{
    auto *ctx = new NgapUeContext(ueId);
    ctx->amfUeNgapId = -1;
    ctx->ranUeNgapId = ++m_ueNgapIdCounter;
    ctx->requestedNssai = std::move(requestedNssai);

    m_ueCtx[ctx->ctxId] = ctx;

    // Perform AMF selection:
    //  1) requested slice (from RegistrationRequest requestedNSSAI, if available)
    //  2) gNB default slice (first configured gNB slice) when slice is not available
    //  3) AMF selection using 5G-S-TMSI (AMF Set ID / AMF Pointer) when available
    NgapAmfContext *amf = nullptr;
    if (requestedSliceType >= 0)
    {
        amf = selectAmf(ueId, requestedSliceType);
        if (!amf)
            m_logger->warn("AMF selection for UE[%d] failed for requested sst[%d]", ueId, requestedSliceType);
    }

    if (!amf && requestedSliceType < 0 && !m_base->config->nssai.slices.empty())
    {
        int32_t defaultSst = static_cast<int32_t>(m_base->config->nssai.slices[0].sst);
        int32_t tmp = defaultSst;
        amf = selectAmf(ueId, tmp);
        if (amf)
            m_logger->debug("AMF selection for UE[%d] used gNB default sst[%d] (no slice info in NAS)", ueId,
                            defaultSst);
        else
            m_logger->warn("AMF selection for UE[%d] failed for gNB default sst[%d] (no slice info in NAS)", ueId,
                           defaultSst);
    }

    if (!amf && sTmsi.has_value())
    {
        // Match AMF by served GUAMI (AMF Set ID / AMF Pointer).
        for (auto &it : m_amfCtx)
        {
            auto *cand = it.second;
            if (!cand || cand->state != EAmfState::CONNECTED)
                continue;
            for (const auto *served : cand->servedGuamiList)
            {
                if (!served)
                    continue;
                if (served->guami.amfSetId == sTmsi->amfSetId && served->guami.amfPointer == sTmsi->amfPointer)
                {
                    amf = cand;
                    break;
                }
            }
            if (amf)
                break;
        }

        if (amf)
        {
            m_logger->debug("AMF selection for UE[%d] matched 5G-S-TMSI amfSetId[%d] amfPointer[%d] -> AMF[%d]", ueId,
                            sTmsi->amfSetId, sTmsi->amfPointer, amf->ctxId);
        }
        else
        {
            m_logger->warn("AMF selection for UE[%d] failed to match 5G-S-TMSI amfSetId[%d] amfPointer[%d]", ueId,
                           sTmsi->amfSetId, sTmsi->amfPointer);
        }
    }

    if (!amf && sTmsi.has_value())
    {
        // Final resort: use the AMF that paged this 5G-S-TMSI (if we recently received Paging from it).
        auto pagingAmfId = findPagingHint(*sTmsi);
        if (pagingAmfId.has_value())
        {
            requestAmfConnectionIfNeeded(*pagingAmfId);
            auto *cand = findAmfContext(*pagingAmfId);
            if (cand && cand->state == EAmfState::CONNECTED)
            {
                amf = cand;
                m_logger->debug("AMF selection for UE[%d] used paging AMF[%d] as final resort", ueId, cand->ctxId);
            }
            else
            {
                m_logger->warn("Paging AMF hint found for UE[%d] -> AMF[%d], but it is not CONNECTED", ueId,
                               *pagingAmfId);
            }
        }
        else
        {
            m_logger->debug("No paging AMF hint found for UE[%d]", ueId);
        }
    }

    if (!amf)
    {
        std::string snapshot;
        bool first = true;
        for (auto &it : m_amfCtx)
        {
            if (!it.second)
                continue;
            if (!first)
                snapshot += "; ";
            first = false;
            snapshot += "AMF[" + std::to_string(it.second->ctxId) + "] state[" + ToString(it.second->state) + "] ";
            snapshot += "plmnSupport[" + std::to_string(it.second->plmnSupportList.size()) + "] ";
            snapshot += "servedGuami[" + std::to_string(it.second->servedGuamiList.size()) + "] ";
            snapshot += "ssts[" + DumpSupportedSsts(*it.second) + "]";
        }
        if (snapshot.empty())
            snapshot = "<no AMF contexts>";

        m_logger->err("AMF selection for UE[%d] failed. requestedSst[%d] hasRequestedNssai[%s] has5gSTmsi[%s]. %s",
                      ueId, requestedSliceType, ctx->requestedNssai.has_value() ? "yes" : "no",
                      sTmsi.has_value() ? "yes" : "no", snapshot.c_str());
        return;
    }

    ctx->associatedAmfId = amf->ctxId;
}

NgapUeContext *NgapTask::findUeContext(int ctxId)
{
    NgapUeContext *ctx = nullptr;
    if (m_ueCtx.count(ctxId))
        ctx = m_ueCtx[ctxId];
    if (ctx == nullptr)
        m_logger->err("UE context not found with id: %d", ctxId);
    return ctx;
}

NgapUeContext *NgapTask::findUeByRanId(int64_t ranUeNgapId)
{
    if (ranUeNgapId <= 0)
        return nullptr;
    // TODO: optimize
    for (auto &ue : m_ueCtx)
        if (ue.second->ranUeNgapId == ranUeNgapId)
            return ue.second;
    return nullptr;
}

NgapUeContext *NgapTask::findUeByAmfId(int64_t amfUeNgapId)
{
    if (amfUeNgapId <= 0)
        return nullptr;
    // TODO: optimize
    for (auto &ue : m_ueCtx)
        if (ue.second->amfUeNgapId == amfUeNgapId)
            return ue.second;
    return nullptr;
}

NgapUeContext *NgapTask::findUeByNgapIdPair(int amfCtxId, const NgapIdPair &idPair)
{
    auto &amfId = idPair.amfUeNgapId;
    auto &ranId = idPair.ranUeNgapId;

    if (!amfId.has_value() && !ranId.has_value())
    {
        sendErrorIndication(amfCtxId, NgapCause::Protocol_abstract_syntax_error_falsely_constructed_message);
        return nullptr;
    }

    if (!amfId.has_value())
    {
        auto ue = findUeByRanId(ranId.value());
        if (ue == nullptr)
        {
            sendErrorIndication(amfCtxId, NgapCause::RadioNetwork_unknown_local_UE_NGAP_ID);
            return nullptr;
        }

        return ue;
    }

    if (!ranId.has_value())
    {
        auto ue = findUeByAmfId(amfId.value());
        if (ue == nullptr)
        {
            sendErrorIndication(amfCtxId, NgapCause::RadioNetwork_inconsistent_remote_UE_NGAP_ID);
            return nullptr;
        }

        return ue;
    }

    auto ue = findUeByRanId(ranId.value());
    if (ue == nullptr)
    {
        sendErrorIndication(amfCtxId, NgapCause::RadioNetwork_unknown_local_UE_NGAP_ID);
        return nullptr;
    }

    if (ue->amfUeNgapId == -1)
        ue->amfUeNgapId = amfId.value();
    else if (ue->amfUeNgapId != amfId.value())
    {
        sendErrorIndication(amfCtxId, NgapCause::RadioNetwork_inconsistent_remote_UE_NGAP_ID);
        return nullptr;
    }

    return ue;
}

void NgapTask::deleteUeContext(int ueId)
{
    auto *ue = m_ueCtx[ueId];
    if (ue)
    {
        delete ue;
        m_ueCtx.erase(ueId);
    }
}

void NgapTask::deleteAmfContext(int amfId)
{
    auto *amf = m_amfCtx[amfId];
    if (amf)
    {
        delete amf;
        m_amfCtx.erase(amfId);
    }
}

} // namespace nr::gnb
