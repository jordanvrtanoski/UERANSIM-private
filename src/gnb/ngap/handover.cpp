//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "encode.hpp"
#include "task.hpp"
#include "utils.hpp"

#include <stdexcept>

#include <gnb/rls/task.hpp>
#include <gnb/gtp/task.hpp>
#include <utils/common.hpp>

#include <lib/rls/ho_phase1.hpp>

#include <asn/ngap/ASN_NGAP_Cause.h>
#include <asn/ngap/ASN_NGAP_GlobalGNB-ID.h>
#include <asn/ngap/ASN_NGAP_GlobalRANNodeID.h>
#include <asn/ngap/ASN_NGAP_GNB-ID.h>
#include <asn/ngap/ASN_NGAP_HandoverCancel.h>
#include <asn/ngap/ASN_NGAP_HandoverCommand.h>
#include <asn/ngap/ASN_NGAP_HandoverCancelAcknowledge.h>
#include <asn/ngap/ASN_NGAP_HandoverFailure.h>
#include <asn/ngap/ASN_NGAP_HandoverPreparationFailure.h>
#include <asn/ngap/ASN_NGAP_HandoverNotify.h>
#include <asn/ngap/ASN_NGAP_HandoverRequest.h>
#include <asn/ngap/ASN_NGAP_HandoverRequestAcknowledge.h>
#include <asn/ngap/ASN_NGAP_HandoverRequestAcknowledgeTransfer.h>
#include <asn/ngap/ASN_NGAP_HandoverRequired.h>
#include <asn/ngap/ASN_NGAP_HandoverRequiredTransfer.h>
#include <asn/ngap/ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequest.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequestAcknowledge.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequestFailure.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequestTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceAdmittedItem.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceItemHORqd.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupItemHOReq.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupRequestTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_QosFlowItemWithDataForwarding.h>
#include <asn/ngap/ASN_NGAP_QosFlowAcceptedItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>
#include <asn/ngap/ASN_NGAP_SourceNGRANNode-ToTargetNGRANNode-TransparentContainer.h>
#include <asn/ngap/ASN_NGAP_TargetNGRANNode-ToSourceNGRANNode-TransparentContainer.h>
#include <asn/ngap/ASN_NGAP_LastVisitedCellItem.h>
#include <asn/ngap/ASN_NGAP_LastVisitedCellInformation.h>
#include <asn/ngap/ASN_NGAP_LastVisitedNGRANCellInformation.h>
#include <asn/ngap/ASN_NGAP_CellType.h>
#include <asn/ngap/ASN_NGAP_CellSize.h>
#include <asn/ngap/ASN_NGAP_NR-CGI.h>
#include <asn/ngap/ASN_NGAP_TargetID.h>
#include <asn/ngap/ASN_NGAP_TargetRANNodeID.h>
#include <asn/ngap/ASN_NGAP_UESecurityCapabilities.h>
#include <asn/ngap/ASN_NGAP_GTPTunnel.h>

namespace nr::gnb
{

static OctetString Ho1TokenToBytes(uint32_t token)
{
    return OctetString::FromOctet4(token);
}

static std::optional<uint32_t> Ho1TokenToU32(const OctetString &tokenBytes)
{
    if (tokenBytes.length() != 4)
        return std::nullopt;
    return tokenBytes.get4UI(0);
}

static void AddHo1TlvUtf8(rls::ho1::Message &msg, uint16_t type, const std::string &v)
{
    OctetString os{};
    os.appendUtf8(v);
    msg.tlvs.push_back(rls::ho1::Tlv{type, std::move(os)});
}

static void AddHo1TlvU64(rls::ho1::Message &msg, uint16_t type, uint64_t v)
{
    msg.tlvs.push_back(rls::ho1::Tlv{type, OctetString::FromOctet8(v)});
}

static std::string NciToHex(int64_t nci)
{
    return "0x" + utils::IntToHex(static_cast<uint64_t>(nci));
}

static ASN_NGAP_NGRAN_CGI_t BuildNgranCgi(const Plmn &plmn, int64_t nci)
{
    ASN_NGAP_NGRAN_CGI_t cgi{};
    cgi.present = ASN_NGAP_NGRAN_CGI_PR_nR_CGI;
    cgi.choice.nR_CGI = asn::New<ASN_NGAP_NR_CGI>();
    ngap_utils::ToPlmnAsn_Ref(plmn, cgi.choice.nR_CGI->pLMNIdentity);
    asn::SetBitStringLong<36>(nci, cgi.choice.nR_CGI->nRCellIdentity);
    return cgi;
}

static ASN_NGAP_UEHistoryInformation_t BuildUeHistoryInformation(const Plmn &plmn, int64_t nci)
{
    ASN_NGAP_UEHistoryInformation_t hist{};
    auto *item = asn::New<ASN_NGAP_LastVisitedCellItem>();
    item->lastVisitedCellInformation.present = ASN_NGAP_LastVisitedCellInformation_PR_nGRANCell;
    item->lastVisitedCellInformation.choice.nGRANCell = asn::New<ASN_NGAP_LastVisitedNGRANCellInformation>();
    auto *ngran = item->lastVisitedCellInformation.choice.nGRANCell;
    ngran->globalCellID = BuildNgranCgi(plmn, nci);
    ngran->cellType.cellSize = ASN_NGAP_CellSize_small;
    ngran->timeUEStayedInCell = 0;
    asn::SequenceAdd(hist, item);
    return hist;
}

static OctetString BuildSourceToTargetTransparentContainer(const Plmn &srcPlmn, int64_t srcNci, const Plmn &tgtPlmn,
                                                           int64_t tgtNci, const OctetString &rrcContainer)
{
    auto *c = asn::New<ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer>();
    asn::SetOctetString(c->rRCContainer, rrcContainer);
    c->targetCell_ID = BuildNgranCgi(tgtPlmn, tgtNci);
    c->uEHistoryInformation = BuildUeHistoryInformation(srcPlmn, srcNci);
    OctetString encoded = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, c);
    asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, c);
    return encoded;
}

static OctetString BuildTargetToSourceTransparentContainer(const OctetString &rrcContainer)
{
    auto *c = asn::New<ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer>();
    asn::SetOctetString(c->rRCContainer, rrcContainer);
    OctetString encoded = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, c);
    asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, c);
    return encoded;
}

std::optional<uint32_t> NgapTask::startN2HandoverPhase1(int ueId, const Plmn &targetPlmn, int targetTac,
                                                        uint32_t targetGnbId, int targetGnbIdLength, int64_t targetNci,
                                                        const std::string &targetName)
{
    auto *ue = findUeContext(ueId);
    if (!ue)
        return std::nullopt;

    auto *amf = findAmfContext(ue->associatedAmfId);
    if (!amf)
        return std::nullopt;

    if (amf->state != EAmfState::CONNECTED)
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_required_tx ho.ue_id=%d ho.fail_reason=amf_not_connected",
                      ueId);
        return std::nullopt;
    }

    uint64_t ueSti = m_base->rlsTask->getStiForUeId(ueId);
    if (ueSti == 0)
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_required_tx ho.ue_id=%d ho.fail_reason=missing_ue_sti",
                      ueId);
        return std::nullopt;
    }

    if (ue->pduSessions.empty())
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_required_tx ho.ue_id=%d ho.fail_reason=no_pdu_sessions",
                      ueId);
        return std::nullopt;
    }

    uint32_t token = ++m_ho1TokenCounter;
    Ho1SourceState st{};
    st.token = token;
    st.targetNci = targetNci;
    st.targetPlmn = targetPlmn;
    st.targetTac = targetTac;
    st.targetGnbId = targetGnbId;
    st.targetGnbIdLength = targetGnbIdLength;
    st.targetName = targetName;
    st.ueSti = ueSti;
    st.startedAtMs = utils::CurrentTimeMillis();
    st.commandReceived = false;

    m_ho1SourceByUe[ueId] = st;
    m_logger->debug("handover ho.role=source ho.state=PREP_SENT ho.ue_id=%d ho.token=%u ho.source.nci=%s "
                    "ho.target.nci=%s ho.target.name=%s",
                    ueId, token, NciToHex(m_base->config->nci).c_str(), NciToHex(targetNci).c_str(),
                    targetName.c_str());

    rls::ho1::Message container{};
    container.msgType = rls::ho1::MsgType::NGAP_SRC_TO_TGT;
    container.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::token, Ho1TokenToBytes(token)});
    AddHo1TlvU64(container, rls::ho1::tlv::ue_sti, ueSti);
    AddHo1TlvU64(container, rls::ho1::tlv::timestamp_ms, static_cast<uint64_t>(st.startedAtMs));

    OctetString rrcContainer = rls::ho1::Encode(container);
    OctetString srcToTgt =
        BuildSourceToTargetTransparentContainer(m_base->config->plmn, m_base->config->nci, targetPlmn, targetNci,
                                                rrcContainer);

    std::vector<ASN_NGAP_HandoverRequiredIEs *> ies;

    auto *ieHoType = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieHoType->id = ASN_NGAP_ProtocolIE_ID_id_HandoverType;
    ieHoType->criticality = ASN_NGAP_Criticality_reject;
    ieHoType->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_HandoverType;
    ieHoType->value.choice.HandoverType = ASN_NGAP_HandoverType_intra5gs;
    ies.push_back(ieHoType);

    auto *ieCause = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(NgapCause::RadioNetwork_ng_intra_system_handover_triggered, ieCause->value.choice.Cause);
    ies.push_back(ieCause);

    auto *ieTarget = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieTarget->id = ASN_NGAP_ProtocolIE_ID_id_TargetID;
    ieTarget->criticality = ASN_NGAP_Criticality_reject;
    ieTarget->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_TargetID;
    ieTarget->value.choice.TargetID.present = ASN_NGAP_TargetID_PR_targetRANNodeID;
    ieTarget->value.choice.TargetID.choice.targetRANNodeID = asn::New<ASN_NGAP_TargetRANNodeID>();

    {
        auto &t = *ieTarget->value.choice.TargetID.choice.targetRANNodeID;
        t.globalRANNodeID.present = ASN_NGAP_GlobalRANNodeID_PR_globalGNB_ID;
        t.globalRANNodeID.choice.globalGNB_ID = asn::New<ASN_NGAP_GlobalGNB_ID>();

        ngap_utils::ToPlmnAsn_Ref(targetPlmn, t.globalRANNodeID.choice.globalGNB_ID->pLMNIdentity);
        t.globalRANNodeID.choice.globalGNB_ID->gNB_ID.present = ASN_NGAP_GNB_ID_PR_gNB_ID;
        asn::SetBitString(t.globalRANNodeID.choice.globalGNB_ID->gNB_ID.choice.gNB_ID, octet4{targetGnbId},
                          static_cast<size_t>(targetGnbIdLength));

        ngap_utils::ToPlmnAsn_Ref(targetPlmn, t.selectedTAI.pLMNIdentity);
        asn::SetOctetString3(t.selectedTAI.tAC, octet3{targetTac});
    }
    ies.push_back(ieTarget);

    auto *iePs = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    iePs->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceListHORqd;
    iePs->criticality = ASN_NGAP_Criticality_reject;
    iePs->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_PDUSessionResourceListHORqd;

    for (int psi : ue->pduSessions)
    {
        auto *tr = asn::New<ASN_NGAP_HandoverRequiredTransfer>();
        OctetString encodedTr = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverRequiredTransfer, tr);
        if (encodedTr.length() == 0)
            throw std::runtime_error("HandoverRequiredTransfer encoding failed");
        asn::Free(asn_DEF_ASN_NGAP_HandoverRequiredTransfer, tr);

        auto *item = asn::New<ASN_NGAP_PDUSessionResourceItemHORqd>();
        item->pDUSessionID = psi;
        asn::SetOctetString(item->handoverRequiredTransfer, encodedTr);
        asn::SequenceAdd(iePs->value.choice.PDUSessionResourceListHORqd, item);
    }

    ies.push_back(iePs);

    auto *ieContainer = asn::New<ASN_NGAP_HandoverRequiredIEs>();
    ieContainer->id = ASN_NGAP_ProtocolIE_ID_id_SourceToTarget_TransparentContainer;
    ieContainer->criticality = ASN_NGAP_Criticality_reject;
    ieContainer->value.present = ASN_NGAP_HandoverRequiredIEs__value_PR_SourceToTarget_TransparentContainer;
    asn::SetOctetString(ieContainer->value.choice.SourceToTarget_TransparentContainer, srcToTgt);
    ies.push_back(ieContainer);

    m_logger->info("handover ho.role=source ho.ngap.event=ho_required_tx ho.ue_id=%d ho.token=%u ho.source.nci=%s "
                   "ho.target.name=%s ho.target.nci=%s ho.target.gnb_id=%u/%d ho.target.tac=%d",
                   ueId, token, NciToHex(m_base->config->nci).c_str(), targetName.c_str(),
                   NciToHex(targetNci).c_str(), targetGnbId, targetGnbIdLength, targetTac);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequired>(ies);
    sendNgapUeAssociated(ueId, pdu);

    return token;
}

void NgapTask::receiveHandoverRequest(int amfId, uint16_t stream, ASN_NGAP_HandoverRequest *msg)
{
    auto *ieAmfUeNgapId = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID);
    if (!ieAmfUeNgapId)
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.fail_reason=missing_amf_ue_ngap_id");
        return;
    }

    int64_t amfUeNgapId = asn::GetSigned64(ieAmfUeNgapId->AMF_UE_NGAP_ID);

    auto *ieContainer = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_SourceToTarget_TransparentContainer);
    if (!ieContainer)
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.amf_ue_ngap_id=%ld ho.fail_reason=missing_container",
                      amfUeNgapId);
        return;
    }

    OctetString srcToTgt = asn::GetOctetString(ieContainer->SourceToTarget_TransparentContainer);
    auto *s2t = ngap_encode::Decode<ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer>(
        asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, srcToTgt.data(),
        static_cast<size_t>(srcToTgt.length()));
    if (!s2t)
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.amf_ue_ngap_id=%ld ho.fail_reason=bad_container",
                      amfUeNgapId);
        return;
    }

    OctetString rrcContainer = asn::GetOctetString(s2t->rRCContainer);
    auto decoded = rls::ho1::Decode(rrcContainer);
    if (!decoded.ok || decoded.message.msgType != rls::ho1::MsgType::NGAP_SRC_TO_TGT)
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.amf_ue_ngap_id=%ld ho.fail_reason=bad_container "
                      "ho.drop_reason=%d",
                      amfUeNgapId, static_cast<int>(decoded.reason));
        asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, s2t);
        return;
    }

    auto tokenBytes = rls::ho1::FindTlvBytes(decoded.message, rls::ho1::tlv::token);
    auto ueStiOpt = rls::ho1::FindTlvU64(decoded.message, rls::ho1::tlv::ue_sti);

    if (!tokenBytes.has_value() || !ueStiOpt.has_value())
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.amf_ue_ngap_id=%ld ho.fail_reason=container_missing_fields",
                      amfUeNgapId);
        asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, s2t);
        return;
    }

    auto tokenOpt = Ho1TokenToU32(*tokenBytes);
    if (!tokenOpt.has_value())
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.amf_ue_ngap_id=%ld ho.fail_reason=invalid_token_len "
                      "ho.token_len=%d",
                      amfUeNgapId, tokenBytes->length());
        asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, s2t);
        return;
    }

    uint32_t token = *tokenOpt;
    uint64_t ueSti = *ueStiOpt;

    int ueId = m_base->rlsTask->reserveUeIdForSti(ueSti);
    if (m_ueCtx.count(ueId))
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.ue_id=%d ho.token=%u ho.fail_reason=ue_context_exists",
                      ueId, token);
        asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, s2t);
        return;
    }

    auto *ue = new NgapUeContext(ueId);
    ue->amfUeNgapId = amfUeNgapId;
    ue->ranUeNgapId = ++m_ueNgapIdCounter;
    ue->associatedAmfId = amfId;
    ue->uplinkStream = (stream == 0) ? 1 : stream;
    ue->downlinkStream = stream;
    m_ueCtx[ueId] = ue;

    auto *ieAmbr = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_UEAggregateMaximumBitRate);
    if (ieAmbr)
    {
        ue->ueAmbr.dlAmbr = asn::GetUnsigned64(ieAmbr->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateDL) / 8ull;
        ue->ueAmbr.ulAmbr = asn::GetUnsigned64(ieAmbr->UEAggregateMaximumBitRate.uEAggregateMaximumBitRateUL) / 8ull;
    }

    {
        auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::UE_CONTEXT_UPDATE);
        w->update = std::make_unique<GtpUeContextUpdate>(true, ueId, ue->ueAmbr);
        m_base->gtpTask->push(std::move(w));
    }

    Ho1TargetState st{};
    st.token = token;
    st.ueId = ueId;
    st.ueSti = ueSti;
    st.preparedAtMs = utils::CurrentTimeMillis();
    st.completeReceived = false;
    st.pathSwitchSent = false;

    auto *ieSecCaps = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_UESecurityCapabilities);
    if (ieSecCaps)
        st.ueSecurityCapabilities =
            asn::UniqueCopy(ieSecCaps->UESecurityCapabilities, asn_DEF_ASN_NGAP_UESecurityCapabilities);

    std::vector<ASN_NGAP_PDUSessionResourceAdmittedItem *> admittedList;
    std::vector<ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck *> failedList;

    auto *ieList = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListHOReq);
    if (ieList)
    {
        auto &list = ieList->PDUSessionResourceSetupListHOReq.list;
        for (int i = 0; i < list.count; i++)
        {
            auto &item = list.array[i];
            auto *transfer = ngap_encode::Decode<ASN_NGAP_PDUSessionResourceSetupRequestTransfer>(
                asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, item->handoverRequestTransfer);
            if (!transfer)
            {
                m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.token=%u ho.ue_id=%d ho.pdu_setup=decode_fail",
                              token, ueId);
                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
                continue;
            }

            auto *resource = new PduSessionResource(ueId, static_cast<int>(item->pDUSessionID));

            auto *ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate);
            if (ie)
            {
                resource->sessionAmbr.dlAmbr =
                    asn::GetUnsigned64(ie->PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateDL) /
                    8ull;
                resource->sessionAmbr.ulAmbr =
                    asn::GetUnsigned64(ie->PDUSessionAggregateMaximumBitRate.pDUSessionAggregateMaximumBitRateUL) /
                    8ull;
            }

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_DataForwardingNotPossible);
            if (ie)
                resource->dataForwardingNotPossible = true;

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_PDUSessionType);
            if (ie)
                resource->sessionType = ngap_utils::PduSessionTypeFromAsn(ie->PDUSessionType);

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation);
            if (ie)
            {
                resource->upTunnel.teid =
                    (uint32_t)asn::GetOctet4(ie->UPTransportLayerInformation.choice.gTPTunnel->gTP_TEID);

                resource->upTunnel.address =
                    asn::GetOctetString(ie->UPTransportLayerInformation.choice.gTPTunnel->transportLayerAddress);
            }

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList);
            if (ie)
            {
                auto *ptr = asn::New<ASN_NGAP_QosFlowSetupRequestList>();
                asn::DeepCopy(asn_DEF_ASN_NGAP_QosFlowSetupRequestList, ie->QosFlowSetupRequestList, ptr);
                resource->qosFlows = asn::WrapUnique(ptr, asn_DEF_ASN_NGAP_QosFlowSetupRequestList);
            }

            auto error = setupPduSessionResource(ue, resource);
            if (error.has_value())
            {
                auto *tr = asn::New<ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer>();
                ngap_utils::ToCauseAsn_Ref(error.value(), tr->cause);

                OctetString encodedTr =
                    ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer, tr);
                if (encodedTr.length() == 0)
                    throw std::runtime_error("HandoverResourceAllocationUnsuccessfulTransfer encoding failed");
                asn::Free(asn_DEF_ASN_NGAP_HandoverResourceAllocationUnsuccessfulTransfer, tr);

                auto *fail = asn::New<ASN_NGAP_PDUSessionResourceFailedToSetupItemHOAck>();
                fail->pDUSessionID = resource->psi;
                asn::SetOctetString(fail->handoverResourceAllocationUnsuccessfulTransfer, encodedTr);
                failedList.push_back(fail);
            }
            else
            {
                HoPduInfo pi{};
                pi.psi = resource->psi;
                pi.downTunnel.teid = resource->downTunnel.teid;
                pi.downTunnel.address = resource->downTunnel.address.copy();
                if (resource->qosFlows)
                {
                    auto &qosList = resource->qosFlows->list;
                    for (int iQos = 0; iQos < qosList.count; iQos++)
                        pi.qfis.push_back(static_cast<uint8_t>(qosList.array[iQos]->qosFlowIdentifier));
                }
                st.pduInfos.push_back(std::move(pi));

                auto *tr = asn::New<ASN_NGAP_HandoverRequestAcknowledgeTransfer>();

                auto &upInfo = tr->dL_NGU_UP_TNLInformation;
                upInfo.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
                upInfo.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
                asn::SetBitString(upInfo.choice.gTPTunnel->transportLayerAddress, resource->downTunnel.address);
                asn::SetOctetString4(upInfo.choice.gTPTunnel->gTP_TEID, (octet4)resource->downTunnel.teid);

                if (resource->qosFlows)
                {
                    auto &qosList = resource->qosFlows->list;
                    for (int iQos = 0; iQos < qosList.count; iQos++)
                    {
                        auto *q = asn::New<ASN_NGAP_QosFlowItemWithDataForwarding>();
                        q->qosFlowIdentifier = qosList.array[iQos]->qosFlowIdentifier;
                        asn::SequenceAdd(tr->qosFlowSetupResponseList, q);
                    }
                }

                OctetString encodedTr =
                    ngap_encode::EncodeS(asn_DEF_ASN_NGAP_HandoverRequestAcknowledgeTransfer, tr);
                if (encodedTr.length() == 0)
                    throw std::runtime_error("HandoverRequestAcknowledgeTransfer encoding failed");
                asn::Free(asn_DEF_ASN_NGAP_HandoverRequestAcknowledgeTransfer, tr);

                auto *adm = asn::New<ASN_NGAP_PDUSessionResourceAdmittedItem>();
                adm->pDUSessionID = resource->psi;
                asn::SetOctetString(adm->handoverRequestAcknowledgeTransfer, encodedTr);
                admittedList.push_back(adm);
            }

            asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
        }
    }

    if (admittedList.empty())
    {
        m_logger->err("handover ho.role=target ho.ngap.event=ho_request_rx ho.token=%u ho.ue_id=%d ho.fail_reason=no_pdu_admitted",
                      token, ueId);
        sendHandoverFailure(ueId, NgapCause::RadioNetwork_no_radio_resources_available_in_target_cell);
        deleteUeContext(ueId);
        asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, s2t);
        return;
    }

    // Build TargetToSource container with token and target link-ip (Phase-1 hint for UE selection).
    rls::ho1::Message t2s{};
    t2s.msgType = rls::ho1::MsgType::NGAP_TGT_TO_SRC;
    t2s.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::token, tokenBytes->copy()});
    AddHo1TlvUtf8(t2s, rls::ho1::tlv::target_link_ip, m_base->config->linkIp);
    AddHo1TlvU64(t2s, rls::ho1::tlv::timestamp_ms, static_cast<uint64_t>(utils::CurrentTimeMillis()));
    OctetString tgtToSrc = BuildTargetToSourceTransparentContainer(rls::ho1::Encode(t2s));

    std::vector<ASN_NGAP_HandoverRequestAcknowledgeIEs *> respIes;

    if (!admittedList.empty())
    {
        auto *ie = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
        ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceAdmittedList;
        ie->criticality = ASN_NGAP_Criticality_ignore;
        ie->value.present = ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceAdmittedList;
        for (auto *x : admittedList)
            asn::SequenceAdd(ie->value.choice.PDUSessionResourceAdmittedList, x);
        respIes.push_back(ie);
    }

    if (!failedList.empty())
    {
        auto *ie = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
        ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListHOAck;
        ie->criticality = ASN_NGAP_Criticality_ignore;
        ie->value.present =
            ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_PDUSessionResourceFailedToSetupListHOAck;
        for (auto *x : failedList)
            asn::SequenceAdd(ie->value.choice.PDUSessionResourceFailedToSetupListHOAck, x);
        respIes.push_back(ie);
    }

    auto *ieT2s = asn::New<ASN_NGAP_HandoverRequestAcknowledgeIEs>();
    ieT2s->id = ASN_NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer;
    ieT2s->criticality = ASN_NGAP_Criticality_reject;
    ieT2s->value.present = ASN_NGAP_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer;
    asn::SetOctetString(ieT2s->value.choice.TargetToSource_TransparentContainer, tgtToSrc);
    respIes.push_back(ieT2s);

    m_ho1TargetByToken[token] = std::move(st);
    m_logger->debug("handover ho.role=target ho.state=PREPARED ho.ue_id=%d ho.token=%u ho.local.nci=%s",
                    ueId, token, NciToHex(m_base->config->nci).c_str());

    m_logger->info("handover ho.role=target ho.ngap.event=ho_request_rx ho.ue_id=%d ho.token=%u ho.amf_ue_ngap_id=%ld "
                   "ho.local.nci=%s ho.pdu_admitted=%d ho.pdu_failed=%d",
                   ueId, token, amfUeNgapId, NciToHex(m_base->config->nci).c_str(),
                   static_cast<int>(admittedList.size()), static_cast<int>(failedList.size()));

    auto *respPdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverRequestAcknowledge>(respIes);
    sendNgapUeAssociated(ueId, respPdu);
    m_logger->info("handover ho.role=target ho.ngap.event=ho_req_ack_tx ho.ue_id=%d ho.token=%u ho.local.nci=%s", ueId,
                   token, NciToHex(m_base->config->nci).c_str());

    // If HO_COMPLETE arrived before preparation finished, execute now.
    if (m_ho1UnmatchedCompleteByToken.count(token))
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_unmatched ho.ue_id=%d ho.token=%u ho.action=replay", ueId,
                        token);
        m_ho1UnmatchedCompleteByToken.erase(token);
        sendHandoverNotify(ueId);
        sendPathSwitchRequest(ueId, m_ho1TargetByToken.at(token));
    }

    asn::Free(asn_DEF_ASN_NGAP_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer, s2t);
}

void NgapTask::receiveHandoverCommand(int amfId, ASN_NGAP_HandoverCommand *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (!ue)
        return;

    if (m_ho1CancelSentAtMsByUe.count(ue->ctxId))
    {
        m_logger->debug("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.action=ignore reason=cancel_sent",
                        ue->ctxId);
        return;
    }

    auto it = m_ho1SourceByUe.find(ue->ctxId);
    if (it == m_ho1SourceByUe.end())
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.fail_reason=no_state", ue->ctxId);
        return;
    }

    auto *ieContainer = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer);
    if (!ieContainer)
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.fail_reason=missing_container",
                      ue->ctxId);
        return;
    }

    OctetString tgtToSrc = asn::GetOctetString(ieContainer->TargetToSource_TransparentContainer);
    auto *t2s = ngap_encode::Decode<ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer>(
        asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, tgtToSrc.data(),
        static_cast<size_t>(tgtToSrc.length()));
    if (!t2s)
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.fail_reason=bad_container",
                      ue->ctxId);
        return;
    }

    OctetString rrcContainer = asn::GetOctetString(t2s->rRCContainer);
    auto decoded = rls::ho1::Decode(rrcContainer);
    if (!decoded.ok || decoded.message.msgType != rls::ho1::MsgType::NGAP_TGT_TO_SRC)
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.fail_reason=bad_container ho.drop_reason=%d",
                      ue->ctxId, static_cast<int>(decoded.reason));
        asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, t2s);
        return;
    }

    auto tokenBytes = rls::ho1::FindTlvBytes(decoded.message, rls::ho1::tlv::token);
    if (!tokenBytes.has_value())
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.fail_reason=missing_token",
                      ue->ctxId);
        asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, t2s);
        return;
    }

    auto tokenOpt = Ho1TokenToU32(*tokenBytes);
    if (!tokenOpt.has_value())
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.fail_reason=invalid_token_len ho.token_len=%d",
                      ue->ctxId, tokenBytes->length());
        asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, t2s);
        return;
    }

    uint32_t token = *tokenOpt;
    if (token != it->second.token)
    {
        m_logger->warn("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.token=%u ho.warn=token_mismatch expected=%u",
                       ue->ctxId, token, it->second.token);
        it->second.token = token;
    }

    auto targetLinkIp = rls::ho1::FindTlvUtf8(decoded.message, rls::ho1::tlv::target_link_ip);
    if (targetLinkIp.has_value())
        it->second.targetLinkIp = *targetLinkIp;

    if (!it->second.targetLinkIp.has_value())
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.token=%u ho.fail_reason=no_target_link_ip",
                      ue->ctxId, token);
        asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, t2s);
        return;
    }

    uint64_t sti = m_base->rlsTask->getStiForUeId(ue->ctxId);
    if (sti == 0)
    {
        m_logger->err("handover ho.role=source ho.ngap.event=ho_command_rx ho.ue_id=%d ho.token=%u ho.fail_reason=missing_ue_sti",
                      ue->ctxId, token);
        sendHandoverCancel(ue->ctxId, NgapCause::RadioNetwork_handover_cancelled);
        m_ho1SourceByUe.erase(ue->ctxId);
        asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, t2s);
        return;
    }

    rls::ho1::Message cmd{};
    cmd.msgType = rls::ho1::MsgType::HO_CMD;
    cmd.tlvs.push_back(rls::ho1::Tlv{rls::ho1::tlv::token, tokenBytes->copy()});
    AddHo1TlvUtf8(cmd, rls::ho1::tlv::target_link_ip, *it->second.targetLinkIp);

    auto w = std::make_unique<NmGnbNgapToRls>(NmGnbNgapToRls::PRIVATE_DATA_TX);
    w->ueId = ue->ctxId;
    w->data = rls::ho1::Encode(cmd);
    m_base->rlsTask->push(std::move(w));

    it->second.commandReceived = true;
    m_logger->debug("handover ho.role=source ho.state=EXECUTING ho.ue_id=%d ho.token=%u", ue->ctxId, token);

    m_logger->info("handover ho.role=source ho.private.event=cmd_tx ho.ue_id=%d ho.token=%u ho.target.name=%s "
                   "ho.target.nci=%s ho.target.link_ip=%s",
                   ue->ctxId, token, it->second.targetName.c_str(), NciToHex(it->second.targetNci).c_str(),
                   it->second.targetLinkIp->c_str());
    asn::Free(asn_DEF_ASN_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer, t2s);
}

void NgapTask::receiveHandoverPreparationFailure(int amfId, ASN_NGAP_HandoverPreparationFailure *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (!ue)
        return;

    if (m_ho1CancelSentAtMsByUe.count(ue->ctxId))
    {
        m_logger->debug("handover ho.role=source ho.ngap.event=ho_prep_fail_rx ho.ue_id=%d ho.action=ignore reason=cancel_sent",
                        ue->ctxId);
        return;
    }

    m_logger->err("handover ho.role=source ho.ngap.event=ho_prep_fail_rx ho.ue_id=%d", ue->ctxId);
    m_ho1SourceByUe.erase(ue->ctxId);
}

void NgapTask::receiveHandoverCancelAcknowledge(int amfId, ASN_NGAP_HandoverCancelAcknowledge *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (!ue)
        return;

    m_logger->info("handover ho.role=source ho.ngap.event=ho_cancel_ack_rx ho.ue_id=%d", ue->ctxId);
    m_ho1SourceByUe.erase(ue->ctxId);
    m_ho1CancelSentAtMsByUe.erase(ue->ctxId);
}

void NgapTask::receivePathSwitchRequestAcknowledge(int amfId, ASN_NGAP_PathSwitchRequestAcknowledge *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (!ue)
        return;

    m_logger->info("handover ho.role=target ho.ngap.event=path_switch_ack_rx ho.ue_id=%d", ue->ctxId);
    m_logger->debug("handover ho.role=target ho.state=SUCCESS ho.ue_id=%d", ue->ctxId);

    for (auto it = m_ho1TargetByToken.begin(); it != m_ho1TargetByToken.end(); ++it)
    {
        if (it->second.ueId == ue->ctxId)
        {
            m_ho1TargetByToken.erase(it);
            break;
        }
    }
}

void NgapTask::receivePathSwitchRequestFailure(int amfId, ASN_NGAP_PathSwitchRequestFailure *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (!ue)
        return;

    m_logger->err("handover ho.role=target ho.ngap.event=path_switch_fail_rx ho.ue_id=%d", ue->ctxId);
    m_logger->debug("handover ho.role=target ho.state=PATH_SWITCH_FAIL ho.ue_id=%d", ue->ctxId);

    for (auto it = m_ho1TargetByToken.begin(); it != m_ho1TargetByToken.end(); ++it)
    {
        if (it->second.ueId == ue->ctxId)
        {
            m_ho1TargetByToken.erase(it);
            break;
        }
    }
}

void NgapTask::handlePrivateMobilityRx(int ueId, OctetString &&payload)
{
    auto decoded = rls::ho1::Decode(payload);
    if (!decoded.ok)
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_drop ho.private.drop_reason=%d",
                        static_cast<int>(decoded.reason));
        return;
    }

    if (decoded.message.msgType != rls::ho1::MsgType::HO_COMPLETE && decoded.message.msgType != rls::ho1::MsgType::HO_FAIL)
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_drop ho.private.drop_reason=unknown_type");
        return;
    }

    auto tokenBytes = rls::ho1::FindTlvBytes(decoded.message, rls::ho1::tlv::token);
    if (!tokenBytes.has_value())
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_drop ho.private.drop_reason=missing_token");
        return;
    }

    auto tokenOpt = Ho1TokenToU32(*tokenBytes);
    if (!tokenOpt.has_value())
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_drop ho.private.drop_reason=invalid_token_len");
        return;
    }

    uint32_t token = *tokenOpt;

    if (decoded.message.msgType == rls::ho1::MsgType::HO_FAIL)
    {
        auto reasonCode = rls::ho1::FindTlvU32(decoded.message, rls::ho1::tlv::reason_code);
        auto reasonDetail = rls::ho1::FindTlvUtf8(decoded.message, rls::ho1::tlv::reason_detail);
        uint32_t reasonCodeVal = reasonCode.has_value() ? *reasonCode : 0;
        const char *reasonDetailStr = reasonDetail.has_value() ? reasonDetail->c_str() : "n/a";

        if (m_ho1TargetByToken.count(token))
        {
            auto &st = m_ho1TargetByToken.at(token);
            m_logger->err("handover ho.role=target ho.private.event=fail_rx ho.ue_id=%d ho.token=%u ho.reason_code=%u ho.detail=%s",
                          ueId, token, reasonCodeVal, reasonDetailStr);
            sendContextRelease(st.ueId, NgapCause::RadioNetwork_ho_failure_in_target_5GC_ngran_node_or_target_system);
            m_ho1TargetByToken.erase(token);
            return;
        }

        if (m_ho1SourceByUe.count(ueId) && m_ho1SourceByUe.at(ueId).token == token)
        {
            m_logger->err("handover ho.role=source ho.private.event=fail_rx ho.ue_id=%d ho.token=%u ho.reason_code=%u ho.detail=%s",
                          ueId, token, reasonCodeVal, reasonDetailStr);
            sendHandoverCancel(ueId, NgapCause::RadioNetwork_handover_cancelled);
            m_ho1SourceByUe.erase(ueId);
            return;
        }

        m_logger->debug("handover ho.role=na ho.private.event=rx_unmatched ho.ue_id=%d ho.token=%u", ueId, token);
        m_ho1UnmatchedCompleteByToken[token] = utils::CurrentTimeMillis();
        return;
    }

    if (!m_ho1TargetByToken.count(token))
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_unmatched ho.ue_id=%d ho.token=%u", ueId, token);
        m_ho1UnmatchedCompleteByToken[token] = utils::CurrentTimeMillis();
        return;
    }

    auto &st = m_ho1TargetByToken.at(token);
    if (st.completeReceived)
    {
        m_logger->debug("handover ho.role=target ho.private.event=rx_dup ho.ue_id=%d ho.token=%u", ueId, token);
        return;
    }
    st.completeReceived = true;

    if (st.ueId != ueId)
    {
        m_logger->warn("handover ho.role=target ho.private.event=complete_rx ho.token=%u ho.ue_id=%d ho.expected_ue_id=%d",
                       token, ueId, st.ueId);
    }
    else
    {
        m_logger->info("handover ho.role=target ho.private.event=complete_rx ho.ue_id=%d ho.token=%u", ueId, token);
    }

    m_logger->debug("handover ho.role=target ho.state=COMPLETE_RX ho.ue_id=%d ho.token=%u", st.ueId, token);
    sendHandoverNotify(st.ueId);
    st.pathSwitchSent = true;
    sendPathSwitchRequest(st.ueId, st);
}

void NgapTask::sendHandoverNotify(int ueId)
{
    std::vector<ASN_NGAP_HandoverNotifyIEs *> ies;
    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverNotify>(ies);
    sendNgapUeAssociated(ueId, pdu);
    m_logger->info("handover ho.role=target ho.ngap.event=ho_notify_tx ho.ue_id=%d", ueId);
}

void NgapTask::sendHandoverFailure(int ueId, NgapCause cause)
{
    std::vector<ASN_NGAP_HandoverFailureIEs *> ies;

    auto *ieCause = asn::New<ASN_NGAP_HandoverFailureIEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_HandoverFailureIEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(cause, ieCause->value.choice.Cause);
    ies.push_back(ieCause);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverFailure>(ies);
    sendNgapUeAssociated(ueId, pdu);
    m_logger->err("handover ho.role=target ho.ngap.event=ho_failure_tx ho.ue_id=%d ho.cause=%d", ueId,
                  static_cast<int>(cause));
}

void NgapTask::sendPathSwitchRequest(int ueId, const Ho1TargetState &st)
{
    auto *ue = findUeContext(ueId);
    if (!ue)
        return;

    if (!st.ueSecurityCapabilities)
    {
        m_logger->err("handover ho.role=target ho.event=path_switch_tx_fail ho.ue_id=%d ho.fail_reason=no_ue_security_caps",
                      ueId);
        return;
    }

    std::vector<ASN_NGAP_PathSwitchRequestIEs *> ies;

    auto *ieCaps = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
    ieCaps->id = ASN_NGAP_ProtocolIE_ID_id_UESecurityCapabilities;
    ieCaps->criticality = ASN_NGAP_Criticality_ignore;
    ieCaps->value.present = ASN_NGAP_PathSwitchRequestIEs__value_PR_UESecurityCapabilities;
    asn::DeepCopy(asn_DEF_ASN_NGAP_UESecurityCapabilities, *st.ueSecurityCapabilities,
                  &ieCaps->value.choice.UESecurityCapabilities);
    ies.push_back(ieCaps);

    auto *ieList = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
    ieList->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList;
    ieList->criticality = ASN_NGAP_Criticality_reject;
    ieList->value.present = ASN_NGAP_PathSwitchRequestIEs__value_PR_PDUSessionResourceToBeSwitchedDLList;

    for (const auto &pi : st.pduInfos)
    {
        auto *tr = asn::New<ASN_NGAP_PathSwitchRequestTransfer>();

        auto &upInfo = tr->dL_NGU_UP_TNLInformation;
        upInfo.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
        upInfo.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
        asn::SetBitString(upInfo.choice.gTPTunnel->transportLayerAddress, pi.downTunnel.address);
        asn::SetOctetString4(upInfo.choice.gTPTunnel->gTP_TEID, (octet4)pi.downTunnel.teid);

        for (uint8_t qfi : pi.qfis)
        {
            auto *q = asn::New<ASN_NGAP_QosFlowAcceptedItem>();
            q->qosFlowIdentifier = qfi;
            asn::SequenceAdd(tr->qosFlowAcceptedList, q);
        }

        OctetString encodedTr = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_PathSwitchRequestTransfer, tr);
        if (encodedTr.length() == 0)
            throw std::runtime_error("PathSwitchRequestTransfer encoding failed");
        asn::Free(asn_DEF_ASN_NGAP_PathSwitchRequestTransfer, tr);

        auto *item = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem>();
        item->pDUSessionID = pi.psi;
        asn::SetOctetString(item->pathSwitchRequestTransfer, encodedTr);
        asn::SequenceAdd(ieList->value.choice.PDUSessionResourceToBeSwitchedDLList, item);
    }

    ies.push_back(ieList);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_PathSwitchRequest>(ies);
    sendNgapUeAssociated(ueId, pdu);

    m_logger->info("handover ho.role=target ho.ngap.event=path_switch_tx ho.ue_id=%d ho.token=%u ho.pdu_count=%d", ueId,
                   st.token, static_cast<int>(st.pduInfos.size()));
    m_logger->debug("handover ho.role=target ho.state=PATH_SWITCH_SENT ho.ue_id=%d ho.token=%u", ueId, st.token);
}

void NgapTask::sendHandoverCancel(int ueId, NgapCause cause)
{
    m_ho1CancelSentAtMsByUe[ueId] = utils::CurrentTimeMillis();

    std::vector<ASN_NGAP_HandoverCancelIEs *> ies;

    auto *ieCause = asn::New<ASN_NGAP_HandoverCancelIEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_HandoverCancelIEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(cause, ieCause->value.choice.Cause);
    ies.push_back(ieCause);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_HandoverCancel>(ies);
    sendNgapUeAssociated(ueId, pdu);
    m_logger->err("handover ho.role=source ho.ngap.event=ho_cancel_tx ho.ue_id=%d ho.cause=%d", ueId,
                  static_cast<int>(cause));
}

void NgapTask::hoHousekeeping(int64_t nowMs)
{
    int64_t TNGRELOCprep = m_base->config->ngapTimers.tngRelocPrepMs;
    int64_t TNGRELOCoverall = m_base->config->ngapTimers.tngRelocOverallMs;
    int64_t preparedTtlMs = m_base->config->ngapTimers.preparedTtlMs;
    int64_t unmatchedCompleteTtlMs = m_base->config->ngapTimers.unmatchedCompleteTtlMs;

    for (auto it = m_ho1SourceByUe.begin(); it != m_ho1SourceByUe.end();)
    {
        auto &st = it->second;
        if (!st.commandReceived && nowMs - st.startedAtMs > TNGRELOCprep)
        {
            m_logger->err("handover ho.role=source ho.timer.name=TNGRELOCprep ho.timer.action=expire ho.ue_id=%d ho.token=%u",
                          it->first, st.token);
            sendHandoverCancel(it->first, NgapCause::RadioNetwork_tngrelocprep_expiry);
            it = m_ho1SourceByUe.erase(it);
            continue;
        }
        if (st.commandReceived && nowMs - st.startedAtMs > TNGRELOCoverall)
        {
            m_logger->err("handover ho.role=source ho.timer.name=TNGRELOCoverall ho.timer.action=expire ho.ue_id=%d "
                          "ho.token=%u ho.target.name=%s ho.target.nci=%s ho.target.link_ip=%s",
                          it->first, st.token, st.targetName.c_str(), NciToHex(st.targetNci).c_str(),
                          st.targetLinkIp.has_value() ? st.targetLinkIp->c_str() : "n/a");
            it = m_ho1SourceByUe.erase(it);
            continue;
        }
        ++it;
    }

    for (auto it = m_ho1TargetByToken.begin(); it != m_ho1TargetByToken.end();)
    {
        auto &st = it->second;
        if (!st.completeReceived && nowMs - st.preparedAtMs > preparedTtlMs)
        {
            int64_t ageMs = nowMs - st.preparedAtMs;
            m_logger->err(
                "handover ho.role=target ho.timer.name=prepared_ttl ho.timer.action=expire ho.ue_id=%d ho.token=%u "
                "ho.local.nci=%s ho.age_ms=%ld ho.ttl_ms=%ld ho.reason=no_ho_complete",
                st.ueId, st.token, NciToHex(m_base->config->nci).c_str(), ageMs, preparedTtlMs);
            sendContextRelease(st.ueId, NgapCause::RadioNetwork_tngrelocoverall_expiry);
            it = m_ho1TargetByToken.erase(it);
            continue;
        }
        if (st.completeReceived && nowMs - st.preparedAtMs > TNGRELOCoverall)
        {
            m_logger->warn(
                "handover ho.role=target ho.timer.name=TNGRELOCoverall ho.timer.action=expire ho.ue_id=%d ho.token=%u",
                st.ueId, st.token);
            it = m_ho1TargetByToken.erase(it);
            continue;
        }
        ++it;
    }

    for (auto it = m_ho1UnmatchedCompleteByToken.begin(); it != m_ho1UnmatchedCompleteByToken.end();)
    {
        if (nowMs - it->second > unmatchedCompleteTtlMs)
        {
            m_logger->debug("handover ho.role=na ho.timer.name=unmatched_complete_ttl ho.timer.action=expire ho.token=%u",
                            it->first);
            it = m_ho1UnmatchedCompleteByToken.erase(it);
            continue;
        }
        ++it;
    }

    // Cancel ignore TTL (avoid permanent ignore if ACK is never received)
    for (auto it = m_ho1CancelSentAtMsByUe.begin(); it != m_ho1CancelSentAtMsByUe.end();)
    {
        if (nowMs - it->second > TNGRELOCprep)
            it = m_ho1CancelSentAtMsByUe.erase(it);
        else
            ++it;
    }
}

} // namespace nr::gnb
