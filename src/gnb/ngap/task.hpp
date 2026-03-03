//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>

#include <gnb/nts.hpp>
#include <gnb/types.hpp>
#include <lib/app/monitor.hpp>
#include <utils/logger.hpp>
#include <utils/nts.hpp>

extern "C"
{
    struct ASN_NGAP_NGAP_PDU;
    struct ASN_NGAP_NGSetupResponse;
    struct ASN_NGAP_NGSetupFailure;
    struct ASN_NGAP_ErrorIndication;
    struct ASN_NGAP_DownlinkNASTransport;
    struct ASN_NGAP_RerouteNASRequest;
    struct ASN_NGAP_PDUSessionResourceSetupRequest;
    struct ASN_NGAP_InitialContextSetupRequest;
    struct ASN_NGAP_UEContextReleaseCommand;
    struct ASN_NGAP_UEContextModificationRequest;
    struct ASN_NGAP_AMFConfigurationUpdate;
    struct ASN_NGAP_OverloadStart;
    struct ASN_NGAP_OverloadStop;
    struct ASN_NGAP_PDUSessionResourceReleaseCommand;
    struct ASN_NGAP_Paging;
    struct ASN_NGAP_HandoverRequired;
    struct ASN_NGAP_HandoverRequest;
    struct ASN_NGAP_HandoverCommand;
    struct ASN_NGAP_HandoverPreparationFailure;
    struct ASN_NGAP_HandoverCancelAcknowledge;
    struct ASN_NGAP_PathSwitchRequestAcknowledge;
    struct ASN_NGAP_PathSwitchRequestFailure;
    struct ASN_NGAP_UESecurityCapabilities;
}

namespace nr::gnb
{

class SctpTask;
class GnbRrcTask;
class GtpTask;
class GnbAppTask;

class NgapTask : public NtsTask
{
  private:
    TaskBase *m_base;
    std::unique_ptr<Logger> m_logger;

    std::unordered_map<int, NgapAmfContext *> m_amfCtx;
    std::unordered_map<int, NgapUeContext *> m_ueCtx;
    int64_t m_ueNgapIdCounter;
    uint32_t m_downlinkTeidCounter;
    bool m_isInitialized;

    struct FiveGSTmsiKey
    {
        int amfSetId{};
        int amfPointer{};
        uint32_t tmsi{};

        bool operator==(const FiveGSTmsiKey &other) const
        {
            return amfSetId == other.amfSetId && amfPointer == other.amfPointer && tmsi == other.tmsi;
        }
    };

    struct FiveGSTmsiKeyHash
    {
        size_t operator()(const FiveGSTmsiKey &k) const
        {
            // Simple mix of three small integers. (No security requirements.)
            size_t h = std::hash<int>{}(k.amfSetId);
            h ^= std::hash<int>{}(k.amfPointer) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
            h ^= std::hash<uint32_t>{}(k.tmsi) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
            return h;
        }
    };

    struct PagingAmfHint
    {
        int amfCtxId{};
        int64_t lastSeenMs{};
    };

    std::unordered_map<FiveGSTmsiKey, PagingAmfHint, FiveGSTmsiKeyHash> m_pagingAmfHints;

    friend class GnbCmdHandler;

    struct HoPduInfo
    {
        int psi{};
        GtpTunnel downTunnel{};
        std::vector<uint8_t> qfis{};
    };

    struct Ho1SourceState
    {
        uint32_t token{};
        int64_t targetNci{};
        int targetGnbIdLength{};
        uint32_t targetGnbId{};
        Plmn targetPlmn{};
        int targetTac{};
        std::string targetName{};

        std::optional<std::string> targetLinkIp{};
        uint64_t ueSti{};
        int64_t startedAtMs{};
        bool commandReceived{};
    };

    struct Ho1TargetState
    {
        uint32_t token{};
        int ueId{};
        uint64_t ueSti{};
        std::vector<HoPduInfo> pduInfos{};
        asn::Unique<ASN_NGAP_UESecurityCapabilities> ueSecurityCapabilities{};
        int64_t preparedAtMs{};
        bool completeReceived{};
        bool pathSwitchSent{};
    };

    uint32_t m_ho1TokenCounter{};
    std::unordered_map<int, Ho1SourceState> m_ho1SourceByUe{};
    std::unordered_map<uint32_t, Ho1TargetState> m_ho1TargetByToken{};
    std::unordered_map<uint32_t, int64_t> m_ho1UnmatchedCompleteByToken{};
    std::unordered_map<int, int64_t> m_ho1CancelSentAtMsByUe{};

  public:
    explicit NgapTask(TaskBase *base);
    ~NgapTask() override = default;

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;

  private:
    /* Utility functions */
    void createAmfContext(const GnbAmfConfig &config);
    NgapAmfContext *findAmfContext(int ctxId);
    void createUeContext(int ueId, int32_t &requestedSliceType, std::optional<NetworkSlice> requestedNssai,
                         const std::optional<GutiMobileIdentity> &sTmsi);
    NgapUeContext *findUeContext(int ctxId);
    NgapUeContext *findUeByRanId(int64_t ranUeNgapId);
    NgapUeContext *findUeByAmfId(int64_t amfUeNgapId);
    NgapUeContext *findUeByNgapIdPair(int amfCtxId, const NgapIdPair &idPair);
    void deleteUeContext(int ueId);
    void deleteAmfContext(int amfId);
    void rememberPagingHint(const GutiMobileIdentity &sTmsi, int amfId);
    std::optional<int> findPagingHint(const GutiMobileIdentity &sTmsi);
    void requestAmfConnectionIfNeeded(int amfId);

    /* Interface management */
    void handleAssociationSetup(int amfId, int ascId, int inCount, int outCount);
    void handleAssociationShutdown(int amfId);
    void sendNgSetupRequest(int amfId);
    void sendErrorIndication(int amfId, NgapCause cause = NgapCause::Protocol_unspecified, int ueId = 0);
    void receiveNgSetupResponse(int amfId, ASN_NGAP_NGSetupResponse *msg);
    void receiveNgSetupFailure(int amfId, ASN_NGAP_NGSetupFailure *msg);
    void receiveErrorIndication(int amfId, ASN_NGAP_ErrorIndication *msg);
    void receiveAmfConfigurationUpdate(int amfId, ASN_NGAP_AMFConfigurationUpdate *msg);
    void receiveOverloadStart(int amfId, ASN_NGAP_OverloadStart *msg);
    void receiveOverloadStop(int amfId, ASN_NGAP_OverloadStop *msg);

    /* Message transport */
    void sendNgapNonUe(int amfId, ASN_NGAP_NGAP_PDU *pdu);
    void sendNgapUeAssociated(int ueId, ASN_NGAP_NGAP_PDU *pdu);
    void handleSctpMessage(int amfId, uint16_t stream, const UniqueBuffer &buffer);
    bool handleSctpStreamId(int amfId, int stream, const ASN_NGAP_NGAP_PDU &pdu);

    /* NAS transport */
    void handleInitialNasTransport(int ueId, OctetString &nasPdu, int64_t rrcEstablishmentCause,
                                   const std::optional<GutiMobileIdentity> &sTmsi);
    void handleUplinkNasTransport(int ueId, const OctetString &nasPdu);
    void receiveDownlinkNasTransport(int amfId, ASN_NGAP_DownlinkNASTransport *msg);
    void deliverDownlinkNas(int ueId, OctetString &&nasPdu);
    void sendNasNonDeliveryIndication(int ueId, const OctetString &nasPdu, NgapCause cause);
    void receiveRerouteNasRequest(int amfId, ASN_NGAP_RerouteNASRequest *msg);

    /* PDU session management */
    void receiveSessionResourceSetupRequest(int amfId, ASN_NGAP_PDUSessionResourceSetupRequest *msg);
    void receiveSessionResourceReleaseCommand(int amfId, ASN_NGAP_PDUSessionResourceReleaseCommand *msg);
    std::optional<NgapCause> setupPduSessionResource(NgapUeContext *ue, PduSessionResource *resource);

    /* UE context management */
    void receiveInitialContextSetup(int amfId, ASN_NGAP_InitialContextSetupRequest *msg);
    void receiveContextRelease(int amfId, ASN_NGAP_UEContextReleaseCommand *msg);
    void receiveContextModification(int amfId, ASN_NGAP_UEContextModificationRequest *msg);
    void sendContextRelease(int ueId, NgapCause cause);

    /* NAS Node Selection */
    NgapAmfContext *selectAmf(int ueId, int32_t &requestedSliceType);
    NgapAmfContext *selectNewAmfForReAllocation(int ueId, int initiatedAmfId, int amfSetId);

    /* Radio resource control */
    void handleRadioLinkFailure(int ueId);
    void receivePaging(int amfId, ASN_NGAP_Paging *msg);

    /* Handover (Phase 1: private mobility) */
    std::optional<uint32_t> startN2HandoverPhase1(int ueId, const Plmn &targetPlmn, int targetTac, uint32_t targetGnbId,
                                                  int targetGnbIdLength, int64_t targetNci,
                                                  const std::string &targetName);
    void receiveHandoverRequest(int amfId, uint16_t stream, ASN_NGAP_HandoverRequest *msg);
    void receiveHandoverCommand(int amfId, ASN_NGAP_HandoverCommand *msg);
    void receiveHandoverPreparationFailure(int amfId, ASN_NGAP_HandoverPreparationFailure *msg);
    void receiveHandoverCancelAcknowledge(int amfId, ASN_NGAP_HandoverCancelAcknowledge *msg);
    void receivePathSwitchRequestAcknowledge(int amfId, ASN_NGAP_PathSwitchRequestAcknowledge *msg);
    void receivePathSwitchRequestFailure(int amfId, ASN_NGAP_PathSwitchRequestFailure *msg);
    void handlePrivateMobilityRx(int ueId, OctetString &&payload);
    void sendHandoverNotify(int ueId);
    void sendPathSwitchRequest(int ueId, const Ho1TargetState &st);
    void sendHandoverCancel(int ueId, NgapCause cause);
    void hoHousekeeping(int64_t nowMs);
};

} // namespace nr::gnb
