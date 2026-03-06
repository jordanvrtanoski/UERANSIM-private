//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "cmd_handler.hpp"

#include <gnb/app/task.hpp>
#include <gnb/gtp/task.hpp>
#include <gnb/ngap/task.hpp>
#include <gnb/rls/task.hpp>
#include <gnb/rrc/task.hpp>
#include <gnb/sctp/task.hpp>
#include <utils/common.hpp>
#include <utils/printer.hpp>

#define PAUSE_CONFIRM_TIMEOUT 3000
#define PAUSE_POLLING 10

namespace nr::gnb
{

void GnbCmdHandler::sendResult(const InetAddress &address, const std::string &output)
{
    m_base->cliCallbackTask->push(std::make_unique<app::NwCliSendResponse>(address, output, false));
}

void GnbCmdHandler::sendError(const InetAddress &address, const std::string &output)
{
    m_base->cliCallbackTask->push(std::make_unique<app::NwCliSendResponse>(address, output, true));
}

void GnbCmdHandler::pauseTasks()
{
    m_base->gtpTask->requestPause();
    m_base->rlsTask->requestPause();
    m_base->ngapTask->requestPause();
    m_base->rrcTask->requestPause();
    m_base->sctpTask->requestPause();
}

void GnbCmdHandler::unpauseTasks()
{
    m_base->gtpTask->requestUnpause();
    m_base->rlsTask->requestUnpause();
    m_base->ngapTask->requestUnpause();
    m_base->rrcTask->requestUnpause();
    m_base->sctpTask->requestUnpause();
}

bool GnbCmdHandler::isAllPaused()
{
    if (!m_base->gtpTask->isPauseConfirmed())
        return false;
    if (!m_base->rlsTask->isPauseConfirmed())
        return false;
    if (!m_base->ngapTask->isPauseConfirmed())
        return false;
    if (!m_base->rrcTask->isPauseConfirmed())
        return false;
    if (!m_base->sctpTask->isPauseConfirmed())
        return false;
    return true;
}

void GnbCmdHandler::handleCmd(NmGnbCliCommand &msg)
{
    pauseTasks();

    uint64_t currentTime = utils::CurrentTimeMillis();
    uint64_t endTime = currentTime + PAUSE_CONFIRM_TIMEOUT;

    bool isPaused = false;
    while (currentTime < endTime)
    {
        currentTime = utils::CurrentTimeMillis();
        if (isAllPaused())
        {
            isPaused = true;
            break;
        }
        utils::Sleep(PAUSE_POLLING);
    }

    if (!isPaused)
    {
        sendError(msg.address, "gNB is unable process command due to pausing timeout");
    }
    else
    {
        handleCmdImpl(msg);
    }

    unpauseTasks();
}

void GnbCmdHandler::handleCmdImpl(NmGnbCliCommand &msg)
{
    switch (msg.cmd->present)
    {
    case app::GnbCliCommand::STATUS: {
        sendResult(msg.address, ToJson(m_base->appTask->m_statusInfo).dumpYaml());
        break;
    }
    case app::GnbCliCommand::INFO: {
        sendResult(msg.address, ToJson(*m_base->config).dumpYaml());
        break;
    }
    case app::GnbCliCommand::AMF_LIST: {
        Json json = Json::Arr({});
        for (auto &amf : m_base->ngapTask->m_amfCtx)
            json.push(Json::Obj({{"id", amf.first}}));
        sendResult(msg.address, json.dumpYaml());
        break;
    }
    case app::GnbCliCommand::AMF_INFO: {
        if (m_base->ngapTask->m_amfCtx.count(msg.cmd->amfId) == 0)
            sendError(msg.address, "AMF not found with given ID");
        else
        {
            auto amf = m_base->ngapTask->m_amfCtx[msg.cmd->amfId];
            sendResult(msg.address, ToJson(*amf).dumpYaml());
        }
        break;
    }
    case app::GnbCliCommand::UE_LIST: {
        Json json = Json::Arr({});
        for (auto &ue : m_base->ngapTask->m_ueCtx)
        {
            json.push(Json::Obj({
                {"ue-id", ue.first},
                {"ran-ngap-id", ue.second->ranUeNgapId},
                {"amf-ngap-id", ue.second->amfUeNgapId},
            }));
        }
        sendResult(msg.address, json.dumpYaml());
        break;
    }
    case app::GnbCliCommand::UE_COUNT: {
        sendResult(msg.address, std::to_string(m_base->ngapTask->m_ueCtx.size()));
        break;
    }
    case app::GnbCliCommand::UE_RELEASE_REQ: {
        if (m_base->ngapTask->m_ueCtx.count(msg.cmd->ueId) == 0)
            sendError(msg.address, "UE not found with given ID");
        else
        {
            auto ue = m_base->ngapTask->m_ueCtx[msg.cmd->ueId];
            m_base->ngapTask->sendContextRelease(ue->ctxId, NgapCause::RadioNetwork_unspecified);
            sendResult(msg.address, "Requesting UE context release");
        }
        break;
    }
    case app::GnbCliCommand::HO_START: {
        if (m_base->ngapTask->m_ueCtx.count(msg.cmd->ueId) == 0)
        {
            sendError(msg.address, "UE not found with given ID");
            break;
        }

        if (m_base->ngapTask->m_ho1SourceByUe.count(msg.cmd->ueId))
        {
            auto token = m_base->ngapTask->m_ho1SourceByUe[msg.cmd->ueId].token;
            sendError(msg.address, "Handover already in progress for this UE (token=" + std::to_string(token) + ")");
            break;
        }

        const auto &neighbors = m_base->config->neighbors;
        if (neighbors.empty())
        {
            sendError(msg.address, "No neighbors configured in gNB config (neighbors: [])");
            break;
        }

        const nr::gnb::GnbNeighborConfig *target = nullptr;
        std::string selector{};
        if (msg.cmd->hoTargetNci.has_value())
        {
            selector = "target-nci";
            for (const auto &n : neighbors)
            {
                if (n.nci == *msg.cmd->hoTargetNci)
                {
                    target = &n;
                    break;
                }
            }
        }
        else if (msg.cmd->hoTargetName.has_value())
        {
            selector = "target-name";
            for (const auto &n : neighbors)
            {
                if (n.name == *msg.cmd->hoTargetName)
                {
                    target = &n;
                    break;
                }
            }
        }
        else if (msg.cmd->hoTargetCellId.has_value())
        {
            selector = "target-cell-id";
            for (const auto &n : neighbors)
            {
                if (n.getCellId() == *msg.cmd->hoTargetCellId)
                {
                    target = &n;
                    break;
                }
            }
        }

        if (!target)
        {
            sendError(msg.address, "Target neighbor not found for selector: " + selector);
            break;
        }

        if (target->nci == m_base->config->nci)
        {
            sendError(msg.address, "Target resolves to the local gNB (refusing self-handover)");
            break;
        }

        auto token = m_base->ngapTask->startN2HandoverPhase1(msg.cmd->ueId, target->plmn, target->tac,
                                                             target->getGnbId(), target->gnbIdLength, target->nci,
                                                             target->name, target->linkIp);
        if (!token.has_value())
        {
            sendError(msg.address, "Handover start failed (see logs for details)");
            break;
        }

        sendResult(msg.address, "Handover triggered (token=" + std::to_string(*token) + ", target=" + target->name +
                                    ")");
        break;
    }
    case app::GnbCliCommand::HO_STATUS: {
        Json json = Json::Obj({});

        int64_t nowMs = utils::CurrentTimeMillis();
        int64_t tPrep = m_base->config->ngapTimers.tngRelocPrepMs;
        int64_t tOverall = m_base->config->ngapTimers.tngRelocOverallMs;
        int64_t tPreparedTtl = m_base->config->ngapTimers.preparedTtlMs;

        Json src = Json::Arr({});
        for (const auto &it : m_base->ngapTask->m_ho1SourceByUe)
        {
            const auto &st = it.second;
            int64_t ageMs = nowMs - st.startedAtMs;
            int64_t remMs = st.commandReceived ? (tOverall - ageMs) : (tPrep - ageMs);
            if (remMs < 0)
                remMs = 0;

            std::string timerName = st.commandReceived ? "TNGRELOCoverall" : "TNGRELOCprep";
            std::string state = st.commandReceived ? "EXECUTING" : "PREP_SENT";

            Json o = Json::Obj({
                {"ue-id", it.first},
                {"token", st.token},
                {"state", state},
                {"target-name", st.targetName},
                {"target-nci", st.targetNci},
                {"target-nci-hex", "0x" + utils::IntToHex(static_cast<uint64_t>(st.targetNci))},
                {"target-tac", st.targetTac},
                {"target-gnb-id", st.targetGnbId},
                {"target-gnb-id-length", st.targetGnbIdLength},
                {"started-at-ms", st.startedAtMs},
                {"age-ms", ageMs},
                {"timer-name", timerName},
                {"timer-ms-remaining", remMs},
            });
            if (st.targetLinkIp.has_value())
                o.put("target-link-ip", *st.targetLinkIp);
            src.push(o);
        }
        json.put("source", src);

        Json tgt = Json::Arr({});
        for (const auto &it : m_base->ngapTask->m_ho1TargetByToken)
        {
            const auto &st = it.second;
            int64_t ageMs = nowMs - st.preparedAtMs;
            int64_t prepRem = tPreparedTtl - ageMs;
            if (prepRem < 0)
                prepRem = 0;
            int64_t overallRem = tOverall - ageMs;
            if (overallRem < 0)
                overallRem = 0;

            tgt.push(Json::Obj({
                {"token", st.token},
                {"ue-id", st.ueId},
                {"ue-sti", "0x" + utils::IntToHex(st.ueSti)},
                {"local-nci", m_base->config->nci},
                {"local-nci-hex", "0x" + utils::IntToHex(static_cast<uint64_t>(m_base->config->nci))},
                {"prepared-at-ms", st.preparedAtMs},
                {"age-ms", ageMs},
                {"pdu-count", static_cast<int>(st.pduInfos.size())},
                {"complete-received", st.completeReceived},
                {"path-switch-sent", st.pathSwitchSent},
                {"prepared-ttl-ms-remaining", prepRem},
                {"TNGRELOCoverall-ms-remaining", overallRem},
            }));
        }
        json.put("target", tgt);

        sendResult(msg.address, json.dumpYaml());
        break;
    }
    case app::GnbCliCommand::HO_CANCEL: {
        if (m_base->ngapTask->m_ueCtx.count(msg.cmd->ueId) == 0)
        {
            sendError(msg.address, "UE not found with given ID");
            break;
        }

        if (!m_base->ngapTask->m_ho1SourceByUe.count(msg.cmd->ueId))
        {
            sendError(msg.address, "No in-progress handover found for this UE");
            break;
        }

        m_base->ngapTask->sendHandoverCancel(msg.cmd->ueId, NgapCause::RadioNetwork_handover_cancelled);
        m_base->ngapTask->m_ho1SourceByUe.erase(msg.cmd->ueId);
        sendResult(msg.address, "Handover cancel requested");
        break;
    }
    }
}

} // namespace nr::gnb
