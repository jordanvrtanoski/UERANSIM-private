//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "xnap.hpp"

namespace asn::xnap
{

static constexpr uint8_t MAGIC_X = 'X';
static constexpr uint8_t MAGIC_N = 'N';
static constexpr uint8_t MAGIC_A = 'A';
static constexpr uint8_t MAGIC_P = 'P';
static constexpr uint8_t VERSION_1 = 1;
static constexpr int HEADER_LEN = 14;
static constexpr int MAX_PAYLOAD_LEN = 8192;
static constexpr uint8_t PAYLOAD_VERSION_1 = 1;

static inline bool IsValidPduClass(uint8_t v)
{
    return v <= static_cast<uint8_t>(XnapPduClass::UnsuccessfulOutcome);
}

static inline bool IsValidProcedureCode(uint8_t v)
{
    return v <= static_cast<uint8_t>(XnapProcedureCode::HandoverCancel);
}

static inline bool IsValidCause(uint8_t v)
{
    return v == static_cast<uint8_t>(XnapCause::Success) ||
           v == static_cast<uint8_t>(XnapCause::HandoverDesirableForRadioReason) ||
           v == static_cast<uint8_t>(XnapCause::UnknownTargetId) ||
           v == static_cast<uint8_t>(XnapCause::NoRadioResourcesAvailable) ||
           v == static_cast<uint8_t>(XnapCause::ProtocolError) ||
           v == static_cast<uint8_t>(XnapCause::Unspecified);
}

bool Encode(const XnapPdu &pdu, OctetString &encoded, std::string &error)
{
    error.clear();
    if (pdu.payload.length() > MAX_PAYLOAD_LEN)
    {
        error = "XnAP payload too large";
        return false;
    }

    encoded = OctetString::Empty();
    encoded.appendOctet(MAGIC_X);
    encoded.appendOctet(MAGIC_N);
    encoded.appendOctet(MAGIC_A);
    encoded.appendOctet(MAGIC_P);
    encoded.appendOctet(VERSION_1);
    encoded.appendOctet(static_cast<uint8_t>(pdu.pduClass));
    encoded.appendOctet(static_cast<uint8_t>(pdu.procedureCode));
    encoded.appendOctet(0);
    encoded.appendOctet4(pdu.transactionId);
    encoded.appendOctet2(static_cast<uint16_t>(pdu.payload.length()));
    encoded.append(pdu.payload);
    return true;
}

bool Decode(const OctetString &encoded, XnapPdu &pdu, std::string &error)
{
    error.clear();
    if (encoded.length() < HEADER_LEN)
    {
        error = "XnAP frame too short";
        return false;
    }

    if (encoded.getI(0) != MAGIC_X || encoded.getI(1) != MAGIC_N || encoded.getI(2) != MAGIC_A || encoded.getI(3) != MAGIC_P)
    {
        error = "XnAP frame magic mismatch";
        return false;
    }

    auto version = static_cast<uint8_t>(encoded.getI(4));
    if (version != VERSION_1)
    {
        error = "XnAP frame version mismatch";
        return false;
    }

    auto pduClass = static_cast<uint8_t>(encoded.getI(5));
    auto procedureCode = static_cast<uint8_t>(encoded.getI(6));
    if (!IsValidPduClass(pduClass))
    {
        error = "XnAP pduClass out of range";
        return false;
    }
    if (!IsValidProcedureCode(procedureCode))
    {
        error = "XnAP procedureCode out of range";
        return false;
    }

    auto payloadLen = encoded.get2I(12);
    if (payloadLen < 0 || payloadLen > MAX_PAYLOAD_LEN)
    {
        error = "XnAP payload length out of range";
        return false;
    }
    if (encoded.length() != HEADER_LEN + payloadLen)
    {
        error = "XnAP payload length mismatch";
        return false;
    }

    pdu.pduClass = static_cast<XnapPduClass>(pduClass);
    pdu.procedureCode = static_cast<XnapProcedureCode>(procedureCode);
    pdu.transactionId = encoded.get4UI(8);
    pdu.payload = encoded.subCopy(HEADER_LEN, payloadLen);
    return true;
}

bool EncodeXnSetupRequest(const XnSetupRequestFields &fields, OctetString &payload, std::string &error)
{
    error.clear();
    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet8(static_cast<uint64_t>(fields.localNci));
    return true;
}

bool DecodeXnSetupRequest(const OctetString &payload, XnSetupRequestFields &fields, std::string &error)
{
    error.clear();
    if (payload.length() != 9)
    {
        error = "XnSetupRequest payload length mismatch";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "XnSetupRequest payload version mismatch";
        return false;
    }
    fields.localNci = static_cast<int64_t>(payload.get8UL(1));
    return true;
}

bool EncodeXnSetupResponse(const XnSetupResponseFields &fields, OctetString &payload, std::string &error)
{
    error.clear();
    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet8(static_cast<uint64_t>(fields.localNci));
    return true;
}

bool DecodeXnSetupResponse(const OctetString &payload, XnSetupResponseFields &fields, std::string &error)
{
    error.clear();
    if (payload.length() != 9)
    {
        error = "XnSetupResponse payload length mismatch";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "XnSetupResponse payload version mismatch";
        return false;
    }
    fields.localNci = static_cast<int64_t>(payload.get8UL(1));
    return true;
}

bool EncodeHandoverPreparationRequest(const HandoverPreparationRequestFields &fields, OctetString &payload,
                                      std::string &error)
{
    error.clear();
    if (fields.pduSessions.size() > 255)
    {
        error = "HandoverPreparationRequest too many PDU sessions";
        return false;
    }

    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet4(static_cast<uint32_t>(fields.ueId));
    payload.appendOctet8(static_cast<uint64_t>(fields.sourceNci));
    payload.appendOctet8(static_cast<uint64_t>(fields.targetNci));
    payload.appendOctet(static_cast<uint8_t>(fields.cause));
    payload.appendOctet8(static_cast<uint64_t>(fields.amfUeNgapId));
    payload.appendOctet4(static_cast<uint32_t>(fields.amfAssociatedId));
    payload.appendOctet8(fields.ueAmbrDl);
    payload.appendOctet8(fields.ueAmbrUl);
    payload.appendOctet(static_cast<uint8_t>(fields.pduSessions.size()));

    for (const auto &session : fields.pduSessions)
    {
        if (session.ulAddress.length() > 255)
        {
            error = "HandoverPreparationRequest UL address too long";
            return false;
        }
        if (session.qfis.size() > 255)
        {
            error = "HandoverPreparationRequest too many QFIs";
            return false;
        }

        payload.appendOctet(session.psi);
        payload.appendOctet(session.sessionType);
        payload.appendOctet8(session.sessionAmbrDl);
        payload.appendOctet8(session.sessionAmbrUl);
        payload.appendOctet4(session.ulTeid);
        payload.appendOctet(static_cast<uint8_t>(session.ulAddress.length()));
        payload.append(session.ulAddress);
        payload.appendOctet(static_cast<uint8_t>(session.qfis.size()));
        for (auto qfi : session.qfis)
            payload.appendOctet(qfi);
    }
    return true;
}

bool DecodeHandoverPreparationRequest(const OctetString &payload, HandoverPreparationRequestFields &fields,
                                      std::string &error)
{
    error.clear();
    if (payload.length() < 55)
    {
        error = "HandoverPreparationRequest payload too short";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "HandoverPreparationRequest payload version mismatch";
        return false;
    }
    fields.oldUeXnapId = payload.get4UI(1);
    fields.ueId = static_cast<int>(payload.get4UI(5));
    fields.sourceNci = static_cast<int64_t>(payload.get8UL(9));
    fields.targetNci = static_cast<int64_t>(payload.get8UL(17));
    auto cause = static_cast<uint8_t>(payload.getI(25));
    if (!IsValidCause(cause))
    {
        error = "HandoverPreparationRequest invalid cause";
        return false;
    }
    fields.cause = static_cast<XnapCause>(cause);
    fields.amfUeNgapId = static_cast<int64_t>(payload.get8UL(26));
    fields.amfAssociatedId = static_cast<int>(payload.get4UI(34));
    fields.ueAmbrDl = payload.get8UL(38);
    fields.ueAmbrUl = payload.get8UL(46);

    int index = 54;
    int pduCount = payload.getI(index++);
    fields.pduSessions.clear();
    fields.pduSessions.reserve(static_cast<size_t>(pduCount));

    for (int i = 0; i < pduCount; i++)
    {
        if (index + 24 > payload.length())
        {
            error = "HandoverPreparationRequest PDU section truncated";
            return false;
        }

        HandoverPreparationRequestFields::PduSessionItem session{};
        session.psi = static_cast<uint8_t>(payload.getI(index++));
        session.sessionType = static_cast<uint8_t>(payload.getI(index++));
        session.sessionAmbrDl = payload.get8UL(index);
        index += 8;
        session.sessionAmbrUl = payload.get8UL(index);
        index += 8;
        session.ulTeid = payload.get4UI(index);
        index += 4;

        int addrLen = payload.getI(index++);
        if (index + addrLen > payload.length())
        {
            error = "HandoverPreparationRequest UL address length mismatch";
            return false;
        }
        session.ulAddress = payload.subCopy(index, addrLen);
        index += addrLen;

        if (index >= payload.length())
        {
            error = "HandoverPreparationRequest missing QFI count";
            return false;
        }
        int qfiCount = payload.getI(index++);
        if (index + qfiCount > payload.length())
        {
            error = "HandoverPreparationRequest QFI length mismatch";
            return false;
        }
        session.qfis.reserve(static_cast<size_t>(qfiCount));
        for (int q = 0; q < qfiCount; q++)
            session.qfis.push_back(static_cast<uint8_t>(payload.getI(index++)));

        fields.pduSessions.push_back(std::move(session));
    }

    if (index != payload.length())
    {
        error = "HandoverPreparationRequest trailing bytes";
        return false;
    }
    return true;
}

bool EncodeHandoverPreparationAcknowledge(const HandoverPreparationAcknowledgeFields &fields, OctetString &payload,
                                          std::string &error)
{
    error.clear();
    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet4(fields.newUeXnapId);
    payload.appendOctet(fields.admittedPduCount);
    payload.appendOctet(fields.failedPduCount);
    return true;
}

bool DecodeHandoverPreparationAcknowledge(const OctetString &payload, HandoverPreparationAcknowledgeFields &fields,
                                          std::string &error)
{
    error.clear();
    if (payload.length() != 11)
    {
        error = "HandoverPreparationAcknowledge payload length mismatch";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "HandoverPreparationAcknowledge payload version mismatch";
        return false;
    }
    fields.oldUeXnapId = payload.get4UI(1);
    fields.newUeXnapId = payload.get4UI(5);
    fields.admittedPduCount = static_cast<uint8_t>(payload.getI(9));
    fields.failedPduCount = static_cast<uint8_t>(payload.getI(10));
    return true;
}

bool EncodeHandoverPreparationFailure(const HandoverPreparationFailureFields &fields, OctetString &payload,
                                      std::string &error)
{
    error.clear();
    if (fields.detail.size() > 255)
    {
        error = "HandoverPreparationFailure detail too long";
        return false;
    }

    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet(static_cast<uint8_t>(fields.cause));
    payload.appendOctet(static_cast<uint8_t>(fields.detail.size()));
    payload.appendUtf8(fields.detail);
    return true;
}

bool DecodeHandoverPreparationFailure(const OctetString &payload, HandoverPreparationFailureFields &fields,
                                      std::string &error)
{
    error.clear();
    if (payload.length() < 7)
    {
        error = "HandoverPreparationFailure payload too short";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "HandoverPreparationFailure payload version mismatch";
        return false;
    }

    auto detailLen = payload.getI(6);
    if (payload.length() != 7 + detailLen)
    {
        error = "HandoverPreparationFailure detail length mismatch";
        return false;
    }

    fields.oldUeXnapId = payload.get4UI(1);
    auto cause = static_cast<uint8_t>(payload.getI(5));
    if (!IsValidCause(cause))
    {
        error = "HandoverPreparationFailure invalid cause";
        return false;
    }
    fields.cause = static_cast<XnapCause>(cause);
    fields.detail = std::string(reinterpret_cast<const char *>(payload.data() + 7), static_cast<size_t>(detailLen));
    return true;
}

bool EncodeSnStatusTransfer(const SnStatusTransferFields &fields, OctetString &payload, std::string &error)
{
    error.clear();
    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet4(fields.newUeXnapId);
    payload.appendOctet(fields.drbCount);
    return true;
}

bool DecodeSnStatusTransfer(const OctetString &payload, SnStatusTransferFields &fields, std::string &error)
{
    error.clear();
    if (payload.length() != 10)
    {
        error = "SnStatusTransfer payload length mismatch";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "SnStatusTransfer payload version mismatch";
        return false;
    }

    fields.oldUeXnapId = payload.get4UI(1);
    fields.newUeXnapId = payload.get4UI(5);
    fields.drbCount = static_cast<uint8_t>(payload.getI(9));
    return true;
}

bool EncodeUeContextRelease(const UeContextReleaseFields &fields, OctetString &payload, std::string &error)
{
    error.clear();
    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet4(fields.newUeXnapId);
    payload.appendOctet(static_cast<uint8_t>(fields.cause));
    return true;
}

bool DecodeUeContextRelease(const OctetString &payload, UeContextReleaseFields &fields, std::string &error)
{
    error.clear();
    if (payload.length() != 10)
    {
        error = "UeContextRelease payload length mismatch";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "UeContextRelease payload version mismatch";
        return false;
    }

    fields.oldUeXnapId = payload.get4UI(1);
    fields.newUeXnapId = payload.get4UI(5);
    auto cause = static_cast<uint8_t>(payload.getI(9));
    if (!IsValidCause(cause))
    {
        error = "UeContextRelease invalid cause";
        return false;
    }
    fields.cause = static_cast<XnapCause>(cause);
    return true;
}

bool EncodeHandoverCancel(const HandoverCancelFields &fields, OctetString &payload, std::string &error)
{
    error.clear();
    if (fields.detail.size() > 255)
    {
        error = "HandoverCancel detail too long";
        return false;
    }

    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet4(fields.newUeXnapId);
    payload.appendOctet(static_cast<uint8_t>(fields.cause));
    payload.appendOctet(static_cast<uint8_t>(fields.detail.size()));
    payload.appendUtf8(fields.detail);
    return true;
}

bool DecodeHandoverCancel(const OctetString &payload, HandoverCancelFields &fields, std::string &error)
{
    error.clear();
    if (payload.length() < 12)
    {
        error = "HandoverCancel payload too short";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "HandoverCancel payload version mismatch";
        return false;
    }

    auto detailLen = payload.getI(11);
    if (payload.length() != 12 + detailLen)
    {
        error = "HandoverCancel detail length mismatch";
        return false;
    }

    fields.oldUeXnapId = payload.get4UI(1);
    fields.newUeXnapId = payload.get4UI(5);
    auto cause = static_cast<uint8_t>(payload.getI(9));
    if (!IsValidCause(cause))
    {
        error = "HandoverCancel invalid cause";
        return false;
    }
    fields.cause = static_cast<XnapCause>(cause);
    fields.detail = std::string(reinterpret_cast<const char *>(payload.data() + 12), static_cast<size_t>(detailLen));
    return true;
}

bool EncodeHandoverCancelAcknowledge(const HandoverCancelAcknowledgeFields &fields, OctetString &payload,
                                     std::string &error)
{
    error.clear();
    payload = OctetString::Empty();
    payload.appendOctet(PAYLOAD_VERSION_1);
    payload.appendOctet4(fields.oldUeXnapId);
    payload.appendOctet4(fields.newUeXnapId);
    return true;
}

bool DecodeHandoverCancelAcknowledge(const OctetString &payload, HandoverCancelAcknowledgeFields &fields,
                                     std::string &error)
{
    error.clear();
    if (payload.length() != 9)
    {
        error = "HandoverCancelAcknowledge payload length mismatch";
        return false;
    }
    if (payload.getI(0) != PAYLOAD_VERSION_1)
    {
        error = "HandoverCancelAcknowledge payload version mismatch";
        return false;
    }

    fields.oldUeXnapId = payload.get4UI(1);
    fields.newUeXnapId = payload.get4UI(5);
    return true;
}

const char *ToString(XnapPduClass pduClass)
{
    switch (pduClass)
    {
    case XnapPduClass::InitiatingMessage:
        return "initiating-message";
    case XnapPduClass::SuccessfulOutcome:
        return "successful-outcome";
    case XnapPduClass::UnsuccessfulOutcome:
        return "unsuccessful-outcome";
    default:
        return "?";
    }
}

const char *ToString(XnapProcedureCode procedureCode)
{
    switch (procedureCode)
    {
    case XnapProcedureCode::XnSetup:
        return "xn-setup";
    case XnapProcedureCode::HandoverPreparation:
        return "handover-preparation";
    case XnapProcedureCode::SnStatusTransfer:
        return "sn-status-transfer";
    case XnapProcedureCode::UeContextRelease:
        return "ue-context-release";
    case XnapProcedureCode::HandoverCancel:
        return "handover-cancel";
    default:
        return "?";
    }
}

const char *ToString(XnapCause cause)
{
    switch (cause)
    {
    case XnapCause::Success:
        return "success";
    case XnapCause::HandoverDesirableForRadioReason:
        return "handover-desirable-for-radio-reason";
    case XnapCause::UnknownTargetId:
        return "unknown-target-id";
    case XnapCause::NoRadioResourcesAvailable:
        return "no-radio-resources-available";
    case XnapCause::ProtocolError:
        return "protocol-error";
    case XnapCause::Unspecified:
        return "unspecified";
    default:
        return "?";
    }
}

} // namespace asn::xnap
