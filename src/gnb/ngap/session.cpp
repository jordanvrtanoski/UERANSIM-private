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

#include <algorithm>
#include <set>
#include <stdexcept>

#include <gnb/gtp/task.hpp>

#include <asn/ngap/ASN_NGAP_AssociatedQosFlowItem.h>
#include <asn/ngap/ASN_NGAP_AssociatedQosFlowList.h>
#include <asn/ngap/ASN_NGAP_GTPTunnel.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToModifyItemModRes.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyItemModReq.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyItemModRes.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyRequest.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyRequestTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyResponse.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyResponseTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceModifyUnsuccessfulTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceFailedToSetupItemSURes.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceReleaseCommand.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceReleaseResponse.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceReleaseResponseTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceReleasedItemRelRes.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupItemSUReq.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupItemSURes.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupRequest.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupRequestTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupResponse.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupResponseTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceToReleaseItemRelCmd.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_QosFlowPerTNLInformationItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowPerTNLInformationList.h>
#include <asn/ngap/ASN_NGAP_QosFlowAddOrModifyRequestItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowAddOrModifyResponseList.h>
#include <asn/ngap/ASN_NGAP_QosFlowAddOrModifyResponseItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowWithCauseItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>
#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestList.h>
#include <asn/ngap/ASN_NGAP_UL-NGU-UP-TNLModifyItem.h>
#include <asn/ngap/ASN_NGAP_UPTransportLayerInformation.h>

namespace nr::gnb
{

void NgapTask::receiveSessionResourceSetupRequest(int amfId, ASN_NGAP_PDUSessionResourceSetupRequest *msg)
{
    std::vector<ASN_NGAP_PDUSessionResourceSetupItemSURes *> successList;
    std::vector<ASN_NGAP_PDUSessionResourceFailedToSetupItemSURes *> failedList;

    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    auto hoIt = m_ho1SourceByUe.find(ue->ctxId);
    if (hoIt != m_ho1SourceByUe.end() && !hoIt->second.commandReceived)
    {
        m_logger->warn(
            "handover ho.role=source ho.event=ho_cancel_due_to_pdu_session_mgmt ho.ue_id=%d ho.token=%u",
            ue->ctxId, hoIt->second.token);
        sendHandoverCancel(ue->ctxId, NgapCause::RadioNetwork_interaction_with_other_procedure);
        m_ho1SourceByUe.erase(hoIt);
    }

    auto *ieList = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListSUReq);
    if (ieList)
    {
        auto &list = ieList->PDUSessionResourceSetupListSUReq.list;
        for (int i = 0; i < list.count; i++)
        {
            auto &item = list.array[i];
            auto *transfer = ngap_encode::Decode<ASN_NGAP_PDUSessionResourceSetupRequestTransfer>(
                asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, item->pDUSessionResourceSetupRequestTransfer);
            if (transfer == nullptr)
            {
                m_logger->err(
                    "Unable to decode a PDU session resource setup request transfer. Ignoring the relevant item");
                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
                continue;
            }

            auto *resource = new PduSessionResource(ue->ctxId, static_cast<int>(item->pDUSessionID));

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
                auto *tr = asn::New<ASN_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer>();
                ngap_utils::ToCauseAsn_Ref(error.value(), tr->cause);

                OctetString encodedTr =
                    ngap_encode::EncodeS(asn_DEF_ASN_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer, tr);

                if (encodedTr.length() == 0)
                    throw std::runtime_error("PDUSessionResourceSetupUnsuccessfulTransfer encoding failed");

                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupUnsuccessfulTransfer, tr);

                auto *res = asn::New<ASN_NGAP_PDUSessionResourceFailedToSetupItemSURes>();
                res->pDUSessionID = resource->psi;
                asn::SetOctetString(res->pDUSessionResourceSetupUnsuccessfulTransfer, encodedTr);

                failedList.push_back(res);
            }
            else
            {
                if (item->pDUSessionNAS_PDU)
                    deliverDownlinkNas(ue->ctxId, asn::GetOctetString(*item->pDUSessionNAS_PDU));

                auto *tr = asn::New<ASN_NGAP_PDUSessionResourceSetupResponseTransfer>();

                auto &qosList = resource->qosFlows->list;
                for (int iQos = 0; iQos < qosList.count; iQos++)
                {
                    auto *associatedQosFlowItem = asn::New<ASN_NGAP_AssociatedQosFlowItem>();
                    associatedQosFlowItem->qosFlowIdentifier = qosList.array[iQos]->qosFlowIdentifier;
                    asn::SequenceAdd(tr->dLQosFlowPerTNLInformation.associatedQosFlowList, associatedQosFlowItem);
                }

                auto &upInfo = tr->dLQosFlowPerTNLInformation.uPTransportLayerInformation;
                upInfo.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
                upInfo.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
                asn::SetBitString(upInfo.choice.gTPTunnel->transportLayerAddress, resource->downTunnel.address);
                asn::SetOctetString4(upInfo.choice.gTPTunnel->gTP_TEID, (octet4)resource->downTunnel.teid);

                OctetString encodedTr =
                    ngap_encode::EncodeS(asn_DEF_ASN_NGAP_PDUSessionResourceSetupResponseTransfer, tr);

                if (encodedTr.length() == 0)
                    throw std::runtime_error("PDUSessionResourceSetupResponseTransfer encoding failed");

                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupResponseTransfer, tr);

                auto *res = asn::New<ASN_NGAP_PDUSessionResourceSetupItemSURes>();
                res->pDUSessionID = resource->psi;
                asn::SetOctetString(res->pDUSessionResourceSetupResponseTransfer, encodedTr);

                successList.push_back(res);
            }

            asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
        }
    }

    auto *ieNasPdu = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_NAS_PDU);
    if (ieNasPdu)
        deliverDownlinkNas(ue->ctxId, asn::GetOctetString(ieNasPdu->NAS_PDU));

    std::vector<ASN_NGAP_PDUSessionResourceSetupResponseIEs *> responseIes;

    if (!successList.empty())
    {
        auto *ie = asn::New<ASN_NGAP_PDUSessionResourceSetupResponseIEs>();
        ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListSURes;
        ie->criticality = ASN_NGAP_Criticality_ignore;
        ie->value.present = ASN_NGAP_PDUSessionResourceSetupResponseIEs__value_PR_PDUSessionResourceSetupListSURes;

        for (auto &item : successList)
            asn::SequenceAdd(ie->value.choice.PDUSessionResourceSetupListSURes, item);

        responseIes.push_back(ie);
    }

    if (!failedList.empty())
    {
        auto *ie = asn::New<ASN_NGAP_PDUSessionResourceSetupResponseIEs>();
        ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceFailedToSetupListSURes;
        ie->criticality = ASN_NGAP_Criticality_ignore;
        ie->value.present =
            ASN_NGAP_PDUSessionResourceSetupResponseIEs__value_PR_PDUSessionResourceFailedToSetupListSURes;

        for (auto &item : failedList)
            asn::SequenceAdd(ie->value.choice.PDUSessionResourceFailedToSetupListSURes, item);

        responseIes.push_back(ie);
    }

    auto *respPdu = asn::ngap::NewMessagePdu<ASN_NGAP_PDUSessionResourceSetupResponse>(responseIes);
    sendNgapUeAssociated(ue->ctxId, respPdu);

    if (failedList.empty())
        m_logger->info("PDU session resource(s) setup for UE[%d] count[%d]", ue->ctxId,
                       static_cast<int>(successList.size()));
    else if (successList.empty())
        m_logger->err("PDU session resource(s) setup was failed for UE[%d] count[%d]", ue->ctxId,
                      static_cast<int>(failedList.size()));
    else
        m_logger->err("PDU session establishment is partially successful for UE[%d], success[%d], failed[%d]",
                      static_cast<int>(successList.size()), static_cast<int>(failedList.size()));
}

void NgapTask::receiveSessionResourceModifyRequest(int amfId, ASN_NGAP_PDUSessionResourceModifyRequest *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    std::vector<ASN_NGAP_PDUSessionResourceModifyItemModRes *> successList;
    std::vector<ASN_NGAP_PDUSessionResourceFailedToModifyItemModRes *> failedList;

    auto makeFailedItem = [](int psi, NgapCause cause) {
        auto *tr = asn::New<ASN_NGAP_PDUSessionResourceModifyUnsuccessfulTransfer>();
        ngap_utils::ToCauseAsn_Ref(cause, tr->cause);

        OctetString encoded = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_PDUSessionResourceModifyUnsuccessfulTransfer, tr);
        asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceModifyUnsuccessfulTransfer, tr);
        if (encoded.length() == 0)
            return static_cast<ASN_NGAP_PDUSessionResourceFailedToModifyItemModRes *>(nullptr);

        auto *fail = asn::New<ASN_NGAP_PDUSessionResourceFailedToModifyItemModRes>();
        fail->pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(psi);
        asn::SetOctetString(fail->pDUSessionResourceModifyUnsuccessfulTransfer, encoded);
        return fail;
    };

    auto *ieList = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceModifyListModReq);
    if (ieList)
    {
        auto &list = ieList->PDUSessionResourceModifyListModReq.list;
        for (int i = 0; i < list.count; i++)
        {
            auto *item = list.array[i];
            if (!item)
                continue;

            const int psi = static_cast<int>(item->pDUSessionID);
            auto *transfer = ngap_encode::Decode<ASN_NGAP_PDUSessionResourceModifyRequestTransfer>(
                asn_DEF_ASN_NGAP_PDUSessionResourceModifyRequestTransfer, item->pDUSessionResourceModifyRequestTransfer);
            if (!transfer)
            {
                if (auto *fail = makeFailedItem(psi, NgapCause::Protocol_transfer_syntax_error))
                    failedList.push_back(fail);
                continue;
            }

            auto snapshot = m_base->gtpTask->getSessionSnapshot(ue->ctxId, psi);
            if (!snapshot.has_value())
            {
                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceModifyRequestTransfer, transfer);
                if (auto *fail = makeFailedItem(psi, NgapCause::RadioNetwork_unknown_PDU_session_ID))
                    failedList.push_back(fail);
                continue;
            }

            auto *resource = new PduSessionResource(ue->ctxId, psi);
            resource->sessionType = snapshot->sessionType;
            resource->sessionAmbr = snapshot->sessionAmbr;
            resource->upTunnel.teid = snapshot->upTunnel.teid;
            resource->upTunnel.address = snapshot->upTunnel.address.copy();
            resource->downTunnel.teid = snapshot->downTunnel.teid;
            resource->downTunnel.address = snapshot->downTunnel.address.copy();

            if (!snapshot->qfis.empty())
            {
                auto *qosSetupList = asn::New<ASN_NGAP_QosFlowSetupRequestList>();
                for (auto qfi : snapshot->qfis)
                {
                    auto *q = asn::New<ASN_NGAP_QosFlowSetupRequestItem>();
                    q->qosFlowIdentifier = static_cast<ASN_NGAP_QosFlowIdentifier_t>(qfi);
                    asn::SequenceAdd(*qosSetupList, q);
                }
                resource->qosFlows = asn::WrapUnique(qosSetupList, asn_DEF_ASN_NGAP_QosFlowSetupRequestList);
            }

            bool parseFailed = false;
            bool sawReleaseList = false;
            std::vector<uint8_t> requestedQfis{};
            std::set<uint8_t> effectiveQfis{};
            for (auto qfi : snapshot->qfis)
            {
                if (qfi >= 1 && qfi <= 63)
                    effectiveQfis.insert(qfi);
            }

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

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLModifyList);
            if (ie && ie->UL_NGU_UP_TNLModifyList.list.count > 0)
            {
                auto *itemTnl = ie->UL_NGU_UP_TNLModifyList.list.array[0];
                if (!itemTnl ||
                    itemTnl->uL_NGU_UP_TNLInformation.present != ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel ||
                    !itemTnl->uL_NGU_UP_TNLInformation.choice.gTPTunnel)
                {
                    parseFailed = true;
                }
                else
                {
                    auto *gtp = itemTnl->uL_NGU_UP_TNLInformation.choice.gTPTunnel;
                    resource->upTunnel.teid = static_cast<uint32_t>(asn::GetOctet4(gtp->gTP_TEID));
                    resource->upTunnel.address = asn::GetOctetString(gtp->transportLayerAddress);
                }
            }

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_QosFlowAddOrModifyRequestList);
            if (ie)
            {
                auto &qosList = ie->QosFlowAddOrModifyRequestList.list;
                for (int iQos = 0; iQos < qosList.count; iQos++)
                {
                    auto *reqQos = qosList.array[iQos];
                    if (!reqQos)
                        continue;
                    auto qfi = static_cast<uint8_t>(reqQos->qosFlowIdentifier);
                    if (qfi < 1 || qfi > 63)
                    {
                        parseFailed = true;
                        continue;
                    }
                    if (std::find(requestedQfis.begin(), requestedQfis.end(), qfi) == requestedQfis.end())
                        requestedQfis.push_back(qfi);
                    effectiveQfis.insert(qfi);
                }
            }

            ie = asn::ngap::GetProtocolIe(transfer, ASN_NGAP_ProtocolIE_ID_id_QosFlowToReleaseList);
            if (ie)
            {
                sawReleaseList = true;
                auto &releaseList = ie->QosFlowListWithCause.list;
                for (int iQos = 0; iQos < releaseList.count; iQos++)
                {
                    auto *releaseItem = releaseList.array[iQos];
                    if (!releaseItem)
                        continue;
                    auto qfi = static_cast<uint8_t>(releaseItem->qosFlowIdentifier);
                    if (qfi < 1 || qfi > 63)
                    {
                        parseFailed = true;
                        continue;
                    }
                    effectiveQfis.erase(qfi);
                }
            }

            auto *qosSetupList = asn::New<ASN_NGAP_QosFlowSetupRequestList>();
            for (auto qfi : effectiveQfis)
            {
                auto *q = asn::New<ASN_NGAP_QosFlowSetupRequestItem>();
                q->qosFlowIdentifier = static_cast<ASN_NGAP_QosFlowIdentifier_t>(qfi);
                asn::SequenceAdd(*qosSetupList, q);
            }
            resource->qosFlows = asn::WrapUnique(qosSetupList, asn_DEF_ASN_NGAP_QosFlowSetupRequestList);
            if (sawReleaseList)
            {
                m_logger->debug("PDU session modify release-list processed UE[%d] PSI[%d] remaining-qfi[%d]", ue->ctxId,
                                psi, static_cast<int>(effectiveQfis.size()));
            }

            if (item->nAS_PDU)
                deliverDownlinkNas(ue->ctxId, asn::GetOctetString(*item->nAS_PDU));

            std::optional<NgapCause> failureCause{};
            if (parseFailed)
                failureCause = NgapCause::Protocol_transfer_syntax_error;
            else if (resource->sessionType != PduSessionType::IPv4 && resource->sessionType != PduSessionType::IPv6 &&
                     resource->sessionType != PduSessionType::IPv4v6)
                failureCause = NgapCause::RadioNetwork_unspecified;
            else if (resource->upTunnel.teid == 0 || resource->upTunnel.address.length() == 0)
                failureCause = NgapCause::Protocol_semantic_error;
            else if ((!resource->qosFlows || resource->qosFlows->list.count == 0) && !sawReleaseList)
                failureCause = NgapCause::Protocol_semantic_error;

            if (failureCause.has_value())
            {
                delete resource;
                asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceModifyRequestTransfer, transfer);
                if (auto *fail = makeFailedItem(psi, *failureCause))
                    failedList.push_back(fail);
                continue;
            }

            GtpTunnel downTunnelForResponse{};
            downTunnelForResponse.teid = resource->downTunnel.teid;
            downTunnelForResponse.address = resource->downTunnel.address.copy();

            auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::SESSION_MODIFY);
            w->resource = resource;
            m_base->gtpTask->push(std::move(w));

            auto *tr = asn::New<ASN_NGAP_PDUSessionResourceModifyResponseTransfer>();
            tr->dL_NGU_UP_TNLInformation = asn::New<ASN_NGAP_UPTransportLayerInformation>();
            tr->dL_NGU_UP_TNLInformation->present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
            tr->dL_NGU_UP_TNLInformation->choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
            asn::SetBitString(tr->dL_NGU_UP_TNLInformation->choice.gTPTunnel->transportLayerAddress,
                              downTunnelForResponse.address);
            asn::SetOctetString4(tr->dL_NGU_UP_TNLInformation->choice.gTPTunnel->gTP_TEID,
                                 static_cast<octet4>(downTunnelForResponse.teid));

            if (!requestedQfis.empty())
            {
                tr->qosFlowAddOrModifyResponseList = asn::New<ASN_NGAP_QosFlowAddOrModifyResponseList>();
                for (auto qfi : requestedQfis)
                {
                    auto *respQfi = asn::New<ASN_NGAP_QosFlowAddOrModifyResponseItem>();
                    respQfi->qosFlowIdentifier = static_cast<ASN_NGAP_QosFlowIdentifier_t>(qfi);
                    asn::SequenceAdd(*tr->qosFlowAddOrModifyResponseList, respQfi);
                }
            }

            OctetString encoded = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_PDUSessionResourceModifyResponseTransfer, tr);
            asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceModifyResponseTransfer, tr);
            asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceModifyRequestTransfer, transfer);
            if (encoded.length() == 0)
            {
                if (auto *fail = makeFailedItem(psi, NgapCause::Protocol_semantic_error))
                    failedList.push_back(fail);
                continue;
            }

            auto *success = asn::New<ASN_NGAP_PDUSessionResourceModifyItemModRes>();
            success->pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(psi);
            asn::SetOctetString(success->pDUSessionResourceModifyResponseTransfer, encoded);
            successList.push_back(success);
        }
    }

    std::vector<ASN_NGAP_PDUSessionResourceModifyResponseIEs *> responseIes{};

    if (!successList.empty())
    {
        auto *ie = asn::New<ASN_NGAP_PDUSessionResourceModifyResponseIEs>();
        ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceModifyListModRes;
        ie->criticality = ASN_NGAP_Criticality_ignore;
        ie->value.present = ASN_NGAP_PDUSessionResourceModifyResponseIEs__value_PR_PDUSessionResourceModifyListModRes;
        for (auto *item : successList)
            asn::SequenceAdd(ie->value.choice.PDUSessionResourceModifyListModRes, item);
        responseIes.push_back(ie);
    }

    if (!failedList.empty())
    {
        auto *ie = asn::New<ASN_NGAP_PDUSessionResourceModifyResponseIEs>();
        ie->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceFailedToModifyListModRes;
        ie->criticality = ASN_NGAP_Criticality_ignore;
        ie->value.present =
            ASN_NGAP_PDUSessionResourceModifyResponseIEs__value_PR_PDUSessionResourceFailedToModifyListModRes;
        for (auto *item : failedList)
            asn::SequenceAdd(ie->value.choice.PDUSessionResourceFailedToModifyListModRes, item);
        responseIes.push_back(ie);
    }

    auto *respPdu = asn::ngap::NewMessagePdu<ASN_NGAP_PDUSessionResourceModifyResponse>(responseIes);
    sendNgapUeAssociated(ue->ctxId, respPdu);

    if (failedList.empty())
        m_logger->info("PDU session resource(s) modified for UE[%d] count[%d]", ue->ctxId,
                       static_cast<int>(successList.size()));
    else if (successList.empty())
        m_logger->err("PDU session resource modification failed for UE[%d] count[%d]", ue->ctxId,
                      static_cast<int>(failedList.size()));
    else
        m_logger->err("PDU session resource modification partially successful for UE[%d] success[%d] failed[%d]",
                      ue->ctxId, static_cast<int>(successList.size()), static_cast<int>(failedList.size()));
}

std::optional<NgapCause> NgapTask::setupPduSessionResource(NgapUeContext *ue, PduSessionResource *resource)
{
    if (resource->sessionType != PduSessionType::IPv4 && resource->sessionType != PduSessionType::IPv6 &&
        resource->sessionType != PduSessionType::IPv4v6)
    {
        m_logger->err("PDU session resource could not setup: session type is not supported psi[%d] type[%d]",
                      static_cast<int>(resource->psi), static_cast<int>(resource->sessionType));
        return NgapCause::RadioNetwork_unspecified;
    }

    if (resource->upTunnel.address.length() == 0)
    {
        m_logger->err("PDU session resource could not setup: Uplink TNL information is missing");
        return NgapCause::Protocol_transfer_syntax_error;
    }

    if (resource->qosFlows == nullptr || resource->qosFlows->list.count == 0)
    {
        m_logger->err("PDU session resource could not setup: QoS flow list is null or empty");
        return NgapCause::Protocol_semantic_error;
    }

    if (resource->downTunnel.teid == 0 || resource->downTunnel.address.length() == 0)
    {
        std::string gtpIp = m_base->config->gtpAdvertiseIp.value_or(m_base->config->gtpIp);
        if (resource->downTunnel.address.length() == 0)
            resource->downTunnel.address = utils::IpToOctetString(gtpIp);
        if (resource->downTunnel.teid == 0)
            resource->downTunnel.teid = ++m_downlinkTeidCounter;
    }

    auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::SESSION_CREATE);
    w->resource = resource;
    m_base->gtpTask->push(std::move(w));

    ue->pduSessions.insert(resource->psi);

    return {};
}

void NgapTask::receiveSessionResourceReleaseCommand(int amfId, ASN_NGAP_PDUSessionResourceReleaseCommand *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    std::set<int> psIds{};

    auto *ieReq = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToReleaseListRelCmd);
    if (ieReq)
    {
        auto &list = ieReq->PDUSessionResourceToReleaseListRelCmd.list;

        for (int i = 0; i < list.count; i++)
        {
            auto &item = list.array[i];
            if (item)
                psIds.insert(static_cast<int>(item->pDUSessionID));
        }
    }

    ieReq = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_NAS_PDU);
    if (ieReq)
        deliverDownlinkNas(ue->ctxId, asn::GetOctetString(ieReq->NAS_PDU));

    auto *ieResp = asn::New<ASN_NGAP_PDUSessionResourceReleaseResponseIEs>();
    ieResp->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceReleasedListRelRes;
    ieResp->criticality = ASN_NGAP_Criticality_ignore;
    ieResp->value.present =
        ASN_NGAP_PDUSessionResourceReleaseResponseIEs__value_PR_PDUSessionResourceReleasedListRelRes;

    // Perform release
    for (auto &psi : psIds)
    {
        auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::SESSION_RELEASE);
        w->ueId = ue->ctxId;
        w->psi = psi;
        m_base->gtpTask->push(std::move(w));

        ue->pduSessions.erase(psi);
    }

    for (auto &psi : psIds)
    {
        auto *tr = asn::New<ASN_NGAP_PDUSessionResourceReleaseResponseTransfer>();

        OctetString encodedTr = ngap_encode::EncodeS(asn_DEF_ASN_NGAP_PDUSessionResourceReleaseResponseTransfer, tr);

        if (encodedTr.length() == 0)
            throw std::runtime_error("PDUSessionResourceReleaseResponseTransfer encoding failed");

        asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceReleaseResponseTransfer, tr);

        auto *item = asn::New<ASN_NGAP_PDUSessionResourceReleasedItemRelRes>();
        item->pDUSessionID = static_cast<ASN_NGAP_PDUSessionID_t>(psi);
        asn::SetOctetString(item->pDUSessionResourceReleaseResponseTransfer, encodedTr);

        asn::SequenceAdd(ieResp->value.choice.PDUSessionResourceReleasedListRelRes, item);
    }

    auto *respPdu = asn::ngap::NewMessagePdu<ASN_NGAP_PDUSessionResourceReleaseResponse>({ieResp});
    sendNgapUeAssociated(ue->ctxId, respPdu);

    m_logger->info("PDU session resource(s) released for UE[%d] count[%d]", ue->ctxId, static_cast<int>(psIds.size()));
}

} // namespace nr::gnb
