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
#include <lib/asn/xnap.hpp>
#include <utils/logger.hpp>
#include <utils/nts.hpp>

namespace nr::gnb
{

enum class EXnPeerState
{
    NOT_CONNECTED = 0,
    CONNECTING,
    CONNECTED,
};

enum class EXnHoTxnState
{
    PREP_SENT = 0,
    ACK_RECEIVED,
    SN_STATUS_SENT,
    CANCEL_SENT,
    CONTEXT_RELEASED,
    CANCELED,
    FAILED,
};

struct XnPeerContext
{
    int clientId{};
    std::string name{};
    std::optional<int64_t> nci{};
    std::string address{};
    uint16_t port{};
    EXnPeerState state{EXnPeerState::NOT_CONNECTED};
    SctpAssociation association{};
    bool setupCompleted{};
    uint32_t nextTransactionId{1};
    int64_t lastConnectAttemptMs{};
};

struct XnSourceHoTxn
{
    uint32_t token{};
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
    int ueId{};
    std::string targetName{};
    int64_t targetNci{};
    int targetGnbIdLength{};
    std::optional<std::string> targetLinkIp{};
    int peerClientId{};
    EXnHoTxnState state{EXnHoTxnState::PREP_SENT};
    bool snStatusSent{};
    int64_t startedAtMs{};
    std::string failureReason{};
};

struct XnTargetHoTxn
{
    uint32_t token{};
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
    int peerClientId{};
    int ueId{};
    int64_t sourceNci{};
    bool snStatusReceived{};
    bool completeReceived{};
    bool contextReleaseSent{};
    int64_t receivedAtMs{};
};

class XnTask : public NtsTask
{
  private:
    static constexpr int TIMER_ID_RECONNECT = 100;
    static constexpr int TIMER_PERIOD_RECONNECT_MS = 1000;
    static constexpr int RECONNECT_INTERVAL_MS = 3000;

    TaskBase *m_base;
    std::unique_ptr<Logger> m_logger;
    std::unordered_map<int, XnPeerContext> m_peers;
    std::unordered_map<uint32_t, XnSourceHoTxn> m_sourceHoByToken;
    std::unordered_map<uint32_t, XnTargetHoTxn> m_targetHoByToken;
    uint32_t m_newUeXnapIdCounter{1};

    friend class GnbCmdHandler;

  public:
    explicit XnTask(TaskBase *base);
    ~XnTask() override = default;

    std::optional<uint32_t> startHandoverPreparation(int ueId, const GnbNeighborConfig &target, std::string &error);
    std::optional<uint32_t> cancelHandoverPreparation(int ueId, std::string &error);
    void onNgapPathSwitchResult(uint32_t token, bool success, int ueId);
    bool isPeerConfiguredForTarget(const GnbNeighborConfig &target) const;
    bool isPeerConnectedForTarget(const GnbNeighborConfig &target) const;

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;

  private:
    void tryConnectPeer(XnPeerContext &peer, int64_t nowMs);
    void handleAssociationSetup(int clientId, int associationId, int inStreams, int outStreams);
    void handleAssociationShutdown(int clientId);
    void handleReceiveMessage(int clientId, const UniqueBuffer &buffer, uint16_t stream);
    void handlePrivateMobilityRx(int ueId, OctetString &&payload);
    bool triggerUeMoveExecution(XnSourceHoTxn &txn);
    void sendXnSetupRequest(XnPeerContext &peer);
    void sendXnSetupResponse(XnPeerContext &peer, uint32_t transactionId, uint16_t stream);
    void sendSnStatusTransfer(XnPeerContext &peer, const asn::xnap::SnStatusTransferFields &fields,
                              uint32_t transactionId, uint16_t stream);
    void sendUeContextRelease(XnPeerContext &peer, const asn::xnap::UeContextReleaseFields &fields,
                              uint32_t transactionId, uint16_t stream);
    void sendHandoverPreparationAcknowledge(XnPeerContext &peer,
                                            const asn::xnap::HandoverPreparationAcknowledgeFields &fields,
                                            uint32_t transactionId, uint16_t stream);
    void sendHandoverPreparationFailure(XnPeerContext &peer, const asn::xnap::HandoverPreparationFailureFields &fields,
                                        uint32_t transactionId, uint16_t stream);
    void sendHandoverCancel(XnPeerContext &peer, const asn::xnap::HandoverCancelFields &fields,
                            uint32_t transactionId, uint16_t stream);
    void sendHandoverCancelAcknowledge(XnPeerContext &peer, const asn::xnap::HandoverCancelAcknowledgeFields &fields,
                                       uint32_t transactionId, uint16_t stream);
    void sendEncoded(int clientId, const OctetString &encoded, uint16_t stream);
    void handleReconnectTick(int64_t nowMs);
    void handleHoHousekeeping(int64_t nowMs);
    std::optional<int> findPeerClientIdForTarget(const GnbNeighborConfig &target) const;
    bool matchesTarget(const XnPeerContext &peer, const GnbNeighborConfig &target) const;
};

Json ToJson(const EXnPeerState &v);
Json ToJson(const EXnHoTxnState &v);

} // namespace nr::gnb
