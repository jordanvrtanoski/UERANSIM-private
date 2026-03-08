//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "sm.hpp"

#include <lib/nas/utils.hpp>
#include <ue/nas/mm/mm.hpp>

namespace nr::ue
{

void NasSm::sendModificationRequest(int psi, const std::optional<nas::IEQoSRules> &requestedQosRules,
                                    const std::optional<nas::IEQoSFlowDescriptions> &requestedQosFlows,
                                    const std::optional<nas::IE5gSmCause> &smCause)
{
    if (m_mm->m_mmSubState == EMmSubState::MM_REGISTERED_NON_ALLOWED_SERVICE && !m_mm->hasEmergency() &&
        !m_mm->isHighPriority())
    {
        m_logger->err("PDU session modification could not start, non allowed service condition");
        return;
    }

    auto &ps = m_pduSessions[psi];
    if (ps->psState != EPsState::ACTIVE)
    {
        m_logger->warn("PDU session modification procedure could not start: PS[%d] is not active", psi);
        return;
    }

    int pti = allocateProcedureTransactionId();
    if (pti == 0)
        return;

    m_logger->debug("Sending PDU Session Modification Request for PSI[%d] pti[%d] qos-rules[%s] qos-flows[%s] "
                    "sm-cause[%s]",
                    psi, pti, requestedQosRules.has_value() ? "yes" : "no", requestedQosFlows.has_value() ? "yes" : "no",
                    smCause.has_value() ? "yes" : "no");

    auto req = std::make_unique<nas::PduSessionModificationRequest>();
    req->pti = pti;
    req->pduSessionId = psi;
    if (requestedQosRules.has_value())
        req->requestedQosRules = nas::utils::DeepCopyIe(*requestedQosRules);
    if (requestedQosFlows.has_value())
        req->requestedQosFlowDescriptions = nas::utils::DeepCopyIe(*requestedQosFlows);
    if (smCause.has_value())
        req->smCause = nas::utils::DeepCopyIe(*smCause);

    ps->psState = EPsState::MODIFICATION_PENDING;

    auto &pt = m_procedureTransactions[pti];
    pt.state = EPtState::PENDING;
    pt.timer = newTransactionTimer(3581);
    pt.message = std::move(req);
    pt.psi = psi;

    sendSmMessage(psi, *pt.message);
}

void NasSm::receiveModificationReject(const nas::PduSessionModificationReject &msg)
{
    m_logger->err("PDU Session Modification Reject received [%s]", nas::utils::EnumToString(msg.smCause.value));

    if (!checkPtiAndPsi(msg))
        return;

    freeProcedureTransactionId(msg.pti);

    auto &ps = m_pduSessions[msg.pduSessionId];
    if (ps->psState != EPsState::MODIFICATION_PENDING)
    {
        m_logger->err("PS modification reject received without being requested");
        sendSmCause(nas::ESmCause::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE, msg.pti, msg.pduSessionId);
        return;
    }

    ps->psState = EPsState::ACTIVE;
}

void NasSm::receiveModificationCommand(const nas::PduSessionModificationCommand &msg)
{
    m_logger->debug("PDU Session Modification Command received");

    int psi = msg.pduSessionId;
    int pti = msg.pti;

    if (psi < PduSession::MIN_ID || psi > PduSession::MAX_ID || m_pduSessions[psi]->psState == EPsState::INACTIVE)
    {
        m_logger->err("PDU Session Modification Command received with invalid PSI[%d]", psi);
        sendSmCause(nas::ESmCause::INVALID_PDU_SESSION_IDENTITY, pti, psi);
        return;
    }

    if (m_pduSessions[psi]->psState == EPsState::ACTIVE_PENDING || m_pduSessions[psi]->psState == EPsState::INACTIVE_PENDING)
    {
        m_logger->warn("PDU Session Modification Command rejected for PSI[%d] due to incompatible protocol state[%d]",
                       psi, static_cast<int>(m_pduSessions[psi]->psState));
        nas::PduSessionModificationCommandReject rej;
        rej.pduSessionId = psi;
        rej.pti = pti;
        rej.smCause.value = nas::ESmCause::MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE;
        sendSmMessage(psi, rej);
        return;
    }

    int pendingPti = 0;
    for (int i = ProcedureTransaction::MIN_ID; i <= ProcedureTransaction::MAX_ID; i++)
    {
        auto &pt = m_procedureTransactions[i];
        if (pt.state == EPtState::PENDING && pt.psi == psi && pt.message &&
            pt.message->messageType == nas::EMessageType::PDU_SESSION_MODIFICATION_REQUEST)
        {
            pendingPti = i;
            break;
        }
    }
    if (pendingPti >= ProcedureTransaction::MIN_ID && pendingPti <= ProcedureTransaction::MAX_ID)
    {
        m_logger->warn("PDU Session Modification Command received during UE-requested modification, aborting local "
                       "procedure PTI[%d] PSI[%d]",
                       pendingPti, psi);
        abortProcedureByPti(pendingPti);
    }

    auto &ps = m_pduSessions[psi];
    if (msg.sessionAmbr.has_value())
        ps->sessionAmbr = nas::utils::DeepCopyIe(*msg.sessionAmbr);
    if (msg.authorizedQoSRules.has_value())
        ps->authorizedQoSRules = nas::utils::DeepCopyIe(*msg.authorizedQoSRules);
    if (msg.authorizedQoSFlowDescriptions.has_value())
        ps->authorizedQoSFlowDescriptions = nas::utils::DeepCopyIe(*msg.authorizedQoSFlowDescriptions);
    ps->psState = EPsState::ACTIVE;

    nas::PduSessionModificationComplete complete;
    complete.pduSessionId = psi;
    complete.pti = pti;
    sendSmMessage(psi, complete);
}

} // namespace nr::ue
