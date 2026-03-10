//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <lib/nas/enums.hpp>
#include <utils/common_types.hpp>

namespace app
{

enum class EHandoverMode
{
    AUTO = 0,
    N2,
    XN
};

enum class EQoSRuleOperationCode : uint8_t
{
    CREATE_NEW = 0b001,
    DELETE_EXISTING = 0b010,
};

enum class EQoSRuleDirection : uint8_t
{
    DOWNLINK = 0b01,
    UPLINK = 0b10,
    BIDIRECTIONAL = 0b11,
};

struct GnbCliCommand
{
    enum PR
    {
        STATUS,
        INFO,
        AMF_LIST,
        AMF_INFO,
        UE_LIST,
        UE_COUNT,
        UE_RELEASE_REQ,
        HO_START,
        HO_STATUS,
        HO_CANCEL,
        XN_PEERS,
    } present;

    // AMF_INFO
    int amfId{};

    // UE_RELEASE_REQ
    int ueId{};

    // HO_START
    std::optional<int64_t> hoTargetNci{};
    std::optional<std::string> hoTargetName{};
    std::optional<int> hoTargetCellId{};
    std::optional<EHandoverMode> hoMode{};

    explicit GnbCliCommand(PR present) : present(present)
    {
    }
};

struct UeCliCommand
{
    enum PR
    {
        INFO,
        STATUS,
        TIMERS,
        PS_ESTABLISH,
        PS_MODIFY,
        PS_RELEASE,
        PS_RELEASE_ALL,
        PS_LIST,
        DE_REGISTER,
        RLS_STATE,
        COVERAGE,
    } present;

    // DE_REGISTER
    EDeregCause deregCause{};

    // PS_RELEASE
    std::array<int8_t, 16> psIds{};
    int psCount{};

    // PS_ESTABLISH
    nas::EPduSessionType psType{nas::EPduSessionType::IPV4};
    std::optional<SingleSlice> sNssai{};
    std::optional<std::string> apn{};
    bool isEmergency{};

    // PS_MODIFY
    int psId{};
    std::optional<std::string> psModifyQosRules{};
    std::optional<std::string> psModifyQosFlows{};
    std::optional<int> psModifySmCause{};
    std::optional<nas::EQoSOperationCode> psModifyFlowOp{};
    std::vector<uint8_t> psModifyFlowQfis{};
    std::optional<bool> psModifyFlowReplacement{};
    std::optional<uint8_t> psModifyFlow5qi{};
    std::optional<EQoSRuleOperationCode> psModifyRuleOp{};
    std::optional<uint8_t> psModifyRuleId{};
    std::optional<uint8_t> psModifyRulePrecedence{};
    std::optional<uint8_t> psModifyRuleQfi{};
    std::optional<bool> psModifyRuleSegregation{};
    std::optional<EQoSRuleDirection> psModifyRuleDirection{};

    explicit UeCliCommand(PR present) : present(present)
    {
    }
};

std::unique_ptr<GnbCliCommand> ParseGnbCliCommand(std::vector<std::string> &&tokens, std::string &error,
                                                  std::string &output);

std::unique_ptr<UeCliCommand> ParseUeCliCommand(std::vector<std::string> &&tokens, std::string &error,
                                                std::string &output);

} // namespace app
