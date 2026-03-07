//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <utils/octet_string.hpp>

namespace asn::xnap
{

enum class XnapPduClass : uint8_t
{
    InitiatingMessage = 0,
    SuccessfulOutcome = 1,
    UnsuccessfulOutcome = 2,
};

enum class XnapProcedureCode : uint8_t
{
    XnSetup = 0,
    HandoverPreparation = 1,
    SnStatusTransfer = 2,
    UeContextRelease = 3,
    HandoverCancel = 4,
};

enum class XnapCause : uint8_t
{
    Success = 0,
    HandoverDesirableForRadioReason = 1,
    UnknownTargetId = 2,
    NoRadioResourcesAvailable = 3,
    ProtocolError = 4,
    Unspecified = 255,
};

struct XnapPdu
{
    XnapPduClass pduClass{XnapPduClass::InitiatingMessage};
    XnapProcedureCode procedureCode{XnapProcedureCode::XnSetup};
    uint32_t transactionId{};
    OctetString payload{};
};

struct XnSetupRequestFields
{
    int64_t localNci{};
};

struct XnSetupResponseFields
{
    int64_t localNci{};
};

struct HandoverPreparationRequestFields
{
    uint32_t oldUeXnapId{};
    int ueId{};
    int64_t sourceNci{};
    int64_t targetNci{};
    XnapCause cause{XnapCause::HandoverDesirableForRadioReason};
    int64_t amfUeNgapId{-1};
    int amfAssociatedId{-1};
    uint64_t ueAmbrDl{};
    uint64_t ueAmbrUl{};
    struct PduSessionItem
    {
        uint8_t psi{};
        uint8_t sessionType{};
        uint64_t sessionAmbrDl{};
        uint64_t sessionAmbrUl{};
        uint32_t ulTeid{};
        OctetString ulAddress{};
        std::vector<uint8_t> qfis{};
    };
    std::vector<PduSessionItem> pduSessions{};
};

struct HandoverPreparationAcknowledgeFields
{
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
    uint8_t admittedPduCount{};
    uint8_t failedPduCount{};
};

struct HandoverPreparationFailureFields
{
    uint32_t oldUeXnapId{};
    XnapCause cause{XnapCause::Unspecified};
    std::string detail{};
};

struct SnStatusTransferFields
{
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
    uint8_t drbCount{};
};

struct UeContextReleaseFields
{
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
    XnapCause cause{XnapCause::Unspecified};
};

struct HandoverCancelFields
{
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
    XnapCause cause{XnapCause::Unspecified};
    std::string detail{};
};

struct HandoverCancelAcknowledgeFields
{
    uint32_t oldUeXnapId{};
    uint32_t newUeXnapId{};
};

bool Encode(const XnapPdu &pdu, OctetString &encoded, std::string &error);
bool Decode(const OctetString &encoded, XnapPdu &pdu, std::string &error);

bool EncodeXnSetupRequest(const XnSetupRequestFields &fields, OctetString &payload, std::string &error);
bool DecodeXnSetupRequest(const OctetString &payload, XnSetupRequestFields &fields, std::string &error);
bool EncodeXnSetupResponse(const XnSetupResponseFields &fields, OctetString &payload, std::string &error);
bool DecodeXnSetupResponse(const OctetString &payload, XnSetupResponseFields &fields, std::string &error);

bool EncodeHandoverPreparationRequest(const HandoverPreparationRequestFields &fields, OctetString &payload,
                                      std::string &error);
bool DecodeHandoverPreparationRequest(const OctetString &payload, HandoverPreparationRequestFields &fields,
                                      std::string &error);

bool EncodeHandoverPreparationAcknowledge(const HandoverPreparationAcknowledgeFields &fields, OctetString &payload,
                                          std::string &error);
bool DecodeHandoverPreparationAcknowledge(const OctetString &payload, HandoverPreparationAcknowledgeFields &fields,
                                          std::string &error);

bool EncodeHandoverPreparationFailure(const HandoverPreparationFailureFields &fields, OctetString &payload,
                                      std::string &error);
bool DecodeHandoverPreparationFailure(const OctetString &payload, HandoverPreparationFailureFields &fields,
                                      std::string &error);

bool EncodeSnStatusTransfer(const SnStatusTransferFields &fields, OctetString &payload, std::string &error);
bool DecodeSnStatusTransfer(const OctetString &payload, SnStatusTransferFields &fields, std::string &error);

bool EncodeUeContextRelease(const UeContextReleaseFields &fields, OctetString &payload, std::string &error);
bool DecodeUeContextRelease(const OctetString &payload, UeContextReleaseFields &fields, std::string &error);

bool EncodeHandoverCancel(const HandoverCancelFields &fields, OctetString &payload, std::string &error);
bool DecodeHandoverCancel(const OctetString &payload, HandoverCancelFields &fields, std::string &error);

bool EncodeHandoverCancelAcknowledge(const HandoverCancelAcknowledgeFields &fields, OctetString &payload,
                                     std::string &error);
bool DecodeHandoverCancelAcknowledge(const OctetString &payload, HandoverCancelAcknowledgeFields &fields,
                                     std::string &error);

const char *ToString(XnapPduClass pduClass);
const char *ToString(XnapProcedureCode procedureCode);
const char *ToString(XnapCause cause);

} // namespace asn::xnap
