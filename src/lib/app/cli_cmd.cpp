//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "cli_cmd.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdint>
#include <optional>
#include <sstream>
#include <utility>

#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <utils/options.hpp>
#include <utils/ordered_map.hpp>

#define CMD_ERR(x)                                                                                                     \
    {                                                                                                                  \
        error = x;                                                                                                     \
        return nullptr;                                                                                                \
    }

class OptionsHandler : public opt::IOptionsHandler
{
  public:
    std::stringstream m_output{};
    std::stringstream m_err{};

  public:
    std::ostream &ostream(bool isError) override
    {
        return isError ? m_err : m_output;
    }

    void status(int code) override
    {
        // nothing to do
    }
};

struct CmdEntry
{
    using DescType = opt::OptionsDescription (*)(const std::string &, const CmdEntry &);

    std::string descriptionText;
    std::string usageText;
    DescType descriptionFunc;
    bool helpIfEmpty;

    CmdEntry() = delete;

    CmdEntry(std::string descriptionText, std::string usageText, DescType descriptionFunc, bool helpIfEmpty)
        : descriptionText(std::move(descriptionText)), usageText(std::move(usageText)),
          descriptionFunc(descriptionFunc), helpIfEmpty(helpIfEmpty)
    {
    }
};

static std::string DumpCommands(const OrderedMap<std::string, CmdEntry> &entryTable)
{
    size_t maxLength = 0;
    for (auto &item : entryTable)
        maxLength = std::max(maxLength, item.size());

    std::stringstream ss{};
    for (auto &item : entryTable)
        ss << item << std::string(maxLength - item.size(), ' ') << " | " << entryTable[item].descriptionText << "\n";
    std::string output = ss.str();

    utils::Trim(output);
    return output;
}

static std::optional<opt::OptionsResult> ParseCliCommandCommon(OrderedMap<std::string, CmdEntry> &cmdEntries,
                                                               std::vector<std::string> &&tokens, std::string &error,
                                                               std::string &output, std::string &subCmd)
{
    if (tokens.empty())
    {
        error = "Empty command";
        return std::nullopt;
    }

    subCmd = tokens[0];

    if (subCmd == "commands" || subCmd == "?")
    {
        output = DumpCommands(cmdEntries);
        return std::nullopt;
    }

    if (cmdEntries.count(subCmd) == 0)
    {
        error = "Command not recognized: " + subCmd;
        return std::nullopt;
    }

    opt::OptionsDescription desc = cmdEntries[subCmd].descriptionFunc(subCmd, cmdEntries[subCmd]);

    OptionsHandler handler{};

    opt::OptionsResult options{tokens, desc, &handler};

    error = handler.m_err.str();
    output = handler.m_output.str();
    utils::Trim(error);
    utils::Trim(output);

    if (!error.empty() || !output.empty())
        return {};

    return options;
}

static bool TryParseInt64Auto(const std::string &s, int64_t &out)
{
    try
    {
        size_t idx = 0;
        long long v = std::stoll(s, &idx, 0);
        if (idx != s.size())
            return false;
        out = static_cast<int64_t>(v);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

//======================================================================================================
//                                      IMPLEMENTATION
//======================================================================================================

static opt::OptionsDescription DefaultDesc(const std::string &subCommand, const CmdEntry &entry)
{
    return {{}, {}, entry.descriptionText, {}, subCommand, {entry.usageText}, {}, entry.helpIfEmpty, true};
}

static opt::OptionsDescription DescForPsEstablish(const std::string &subCommand, const CmdEntry &entry)
{
    std::string example1 = "IPv4 --sst 1 --sd 1 --dnn internet";
    std::string example2 = "IPv4 --emergency";
    std::string example3 = "IPv6 --sst 1 --sd 1 --dnn internet";
    std::string example4 = "IPv4v6 --sst 1 --sd 1 --dnn internet";

    auto res = opt::OptionsDescription{
        {},  {}, entry.descriptionText, {}, subCommand, {entry.usageText}, {example1, example2, example3, example4},
        entry.helpIfEmpty,
        true};

    res.items.emplace_back(std::nullopt, "sst", "SST value of the PDU session", "value");
    res.items.emplace_back(std::nullopt, "sd", "SD value of the PDU session", "value");
    res.items.emplace_back('n', "dnn", "DNN/APN value of the PDU session", "apn");
    res.items.emplace_back('e', "emergency", "Request as an emergency session", std::nullopt);

    return res;
}

static opt::OptionsDescription DescForPsModify(const std::string &subCommand, const CmdEntry &entry)
{
    auto res = opt::OptionsDescription{{},
                                       {},
                                       entry.descriptionText,
                                       {},
                                       subCommand,
                                       {entry.usageText},
                                       {"1 --flow-op modify --flow-qfi 1 --flow-mode replace --flow-5qi 9",
                                        "1 --flow-op delete --flow-qfi 1",
                                        "1 --flow-op create --flow-qfi 2 --flow-5qi 1",
                                        "1 --rule-op create --rule-id 0 --rule-qfi 0 --rule-precedence 100 --rule-dir ul",
                                        "1 --rule-op create --rule-id 0 --rule-qfi 2 --rule-precedence 100 --rule-dir bi --rule-remote-ipv4 8.8.8.8/32",
                                        "1 --flow-op create --flow-qfi 0 --flow-5qi 9 --rule-op create --rule-id 0 "
                                        "--rule-qfi 0 --rule-precedence 100 --rule-dir ul",
                                        "1 --qos-rules 010300020140"},
                                       entry.helpIfEmpty,
                                       true};

    res.items.emplace_back(std::nullopt, "qos-rules", "Requested QoS rules IE payload (hex, no spaces)", "hex");
    res.items.emplace_back(std::nullopt, "qos-flows",
                           "Requested QoS flow descriptions IE payload (hex, no spaces)", "hex");
    res.items.emplace_back(std::nullopt, "flow-op",
                           "Generate QoS flow description operation (modify|create|delete)", "op");
    res.items.emplace_back(std::nullopt, "flow-qfi",
                           "QFI list for --flow-op (comma-separated). Use [1..63] for explicit QFI, or 0 for network-assigned on create.",
                           "list");
    res.items.emplace_back(std::nullopt, "flow-mode",
                           "Flow update mode for --flow-op modify (replace|extend), default: replace", "mode");
    res.items.emplace_back(std::nullopt, "flow-5qi",
                           "5QI parameter for generated flow description (required for create/modify)", "value");
    res.items.emplace_back(std::nullopt, "rule-op",
                           "Generate QoS rule operation (create|delete)", "op");
    res.items.emplace_back(std::nullopt, "rule-id",
                           "QoS Rule Identifier (QRI) for generated rule (0..255)", "value");
    res.items.emplace_back(std::nullopt, "rule-qfi",
                           "QFI in generated rule (0..63). For create with new flow, use 0.", "value");
    res.items.emplace_back(std::nullopt, "rule-precedence",
                           "QoS rule precedence (0..255 except 80) for rule create", "value");
    res.items.emplace_back(std::nullopt, "rule-dir",
                           "Packet filter direction for generated match-all rule (ul|dl|bi), default: bi", "dir");
    res.items.emplace_back(std::nullopt, "rule-remote-ipv4",
                           "Packet filter remote IPv4 match (CIDR), e.g. 8.8.8.8/32", "cidr");
    res.items.emplace_back(std::nullopt, "rule-seg",
                           "Segregation bit for rule create (on|off), default: on", "state");
    res.items.emplace_back(std::nullopt, "sm-cause", "5GSM cause value (0..255)", "value");

    return res;
}

static opt::OptionsDescription DescForHoStart(const std::string &subCommand, const CmdEntry &entry)
{
    auto res = opt::OptionsDescription{{},
                                       {},
                                       entry.descriptionText,
                                       {},
                                       subCommand,
                                       {entry.usageText},
                                       {"1 --target-nci 0x0000000010 --mode auto",
                                        "1 --target-name UERANSIM-gnb-999-1-2 --mode xn",
                                        "1 --target-cell-id 16 --mode n2"},
                                       entry.helpIfEmpty,
                                       true};

    res.items.emplace_back(std::nullopt, "target-nci", "Target gNB NCI (hex or decimal)", "nci");
    res.items.emplace_back(std::nullopt, "target-name", "Target gNB neighbor name", "name");
    res.items.emplace_back(std::nullopt, "target-cell-id", "Target cell ID (as derived from NCI)", "cell-id");
    res.items.emplace_back(std::nullopt, "mode", "Handover mode selection (auto|n2|xn)", "mode");
    return res;
}

namespace app
{

static OrderedMap<std::string, CmdEntry> g_gnbCmdEntries = {
    {"info", {"Show some information about the gNB", "", DefaultDesc, false}},
    {"status", {"Show some status information about the gNB", "", DefaultDesc, false}},
    {"amf-list", {"List all AMFs associated with the gNB", "", DefaultDesc, false}},
    {"amf-info", {"Show some status information about the given AMF", "<amf-id>", DefaultDesc, true}},
    {"ue-list", {"List all UEs associated with the gNB", "", DefaultDesc, false}},
    {"ue-count", {"Print the total number of UEs connected the this gNB", "", DefaultDesc, false}},
    {"ue-release", {"Request a UE context release for the given UE", "<ue-id>", DefaultDesc, false}},
    {"ho-start",
     {"Trigger a handover (mode: auto|n2|xn)", "<ue-id> --target-... <value> [--mode <auto|n2|xn>]", DescForHoStart,
      true}},
    {"ho-status", {"Show active handover state (debug)", "", DefaultDesc, false}},
    {"ho-cancel", {"Cancel an in-progress handover", "<ue-id>", DefaultDesc, true}},
    {"xn-peers", {"Show configured Xn peers and SCTP states", "", DefaultDesc, false}},
};

static OrderedMap<std::string, CmdEntry> g_ueCmdEntries = {
    {"info", {"Show some information about the UE", "", DefaultDesc, false}},
    {"status", {"Show some status information about the UE", "", DefaultDesc, false}},
    {"timers", {"Dump current status of the timers in the UE", "", DefaultDesc, false}},
    {"rls-state", {"Show status information about RLS", "", DefaultDesc, false}},
    {"coverage", {"Dump available cells and PLMNs in the coverage", "", DefaultDesc, false}},
    {"ps-establish",
     {"Trigger a PDU session establishment procedure", "<IPv4|IPv6|IPv4v6> [options]", DescForPsEstablish, true}},
    {"ps-modify", {"Trigger a PDU session modification procedure", "<pdu-session-id> [options]", DescForPsModify,
                   true}},
    {"ps-list", {"List all PDU sessions", "", DefaultDesc, false}},
    {"ps-release", {"Trigger a PDU session release procedure", "<pdu-session-id>...", DefaultDesc, true}},
    {"ps-release-all", {"Trigger PDU session release procedures for all active sessions", "", DefaultDesc, false}},
    {"deregister",
     {"Perform a de-registration by the UE", "<normal|disable-5g|switch-off|remove-sim>", DefaultDesc, true}},
};

static std::unique_ptr<GnbCliCommand> GnbCliParseImpl(const std::string &subCmd, const opt::OptionsResult &options,
                                                      std::string &error)
{
    if (subCmd == "info")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::INFO);
    }
    if (subCmd == "status")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::STATUS);
    }
    else if (subCmd == "amf-list")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::AMF_LIST);
    }
    else if (subCmd == "amf-info")
    {
        auto cmd = std::make_unique<GnbCliCommand>(GnbCliCommand::AMF_INFO);
        if (options.positionalCount() == 0)
            CMD_ERR("AMF ID is expected")
        if (options.positionalCount() > 1)
            CMD_ERR("Only one AMF ID is expected")
        cmd->amfId = utils::ParseInt(options.getPositional(0));
        if (cmd->amfId <= 0)
            CMD_ERR("Invalid AMF ID")
        return cmd;
    }
    else if (subCmd == "ue-list")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::UE_LIST);
    }
    else if (subCmd == "ue-count")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::UE_COUNT);
    }
    else if (subCmd == "ue-release")
    {
        auto cmd = std::make_unique<GnbCliCommand>(GnbCliCommand::UE_RELEASE_REQ);
        if (options.positionalCount() == 0)
            CMD_ERR("UE ID is expected")
        if (options.positionalCount() > 1)
            CMD_ERR("Only one UE ID is expected")
        cmd->ueId = utils::ParseInt(options.getPositional(0));
        if (cmd->ueId <= 0)
            CMD_ERR("Invalid UE ID")
        return cmd;
    }
    else if (subCmd == "ho-start")
    {
        auto cmd = std::make_unique<GnbCliCommand>(GnbCliCommand::HO_START);
        if (options.positionalCount() == 0)
            CMD_ERR("UE ID is expected")
        if (options.positionalCount() > 1)
            CMD_ERR("Only one UE ID is expected")
        cmd->ueId = utils::ParseInt(options.getPositional(0));
        if (cmd->ueId <= 0)
            CMD_ERR("Invalid UE ID")

        auto hasOpt = [&options](const char *name) {
            return options.hasFlag(std::nullopt, std::optional<std::string>{std::string{name}});
        };
        auto getOpt = [&options](const char *name) {
            return options.getOption(std::nullopt, std::optional<std::string>{std::string{name}});
        };

        int selectorCount = 0;
        if (hasOpt("target-nci"))
        {
            int64_t tmp = 0;
            if (!TryParseInt64Auto(getOpt("target-nci"), tmp) || tmp < 0)
                CMD_ERR("Invalid --target-nci value")
            cmd->hoTargetNci = tmp;
            selectorCount++;
        }
        if (hasOpt("target-name"))
        {
            cmd->hoTargetName = getOpt("target-name");
            selectorCount++;
        }
        if (hasOpt("target-cell-id"))
        {
            cmd->hoTargetCellId = utils::ParseInt(getOpt("target-cell-id"));
            selectorCount++;
        }
        if (hasOpt("mode"))
        {
            std::string mode = getOpt("mode");
            std::transform(mode.begin(), mode.end(), mode.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (mode == "auto")
                cmd->hoMode = EHandoverMode::AUTO;
            else if (mode == "n2")
                cmd->hoMode = EHandoverMode::N2;
            else if (mode == "xn")
                cmd->hoMode = EHandoverMode::XN;
            else
                CMD_ERR("Invalid --mode value, possible values are: auto, n2, xn")
        }

        if (selectorCount == 0)
            CMD_ERR("Target selector is required: --target-nci, --target-name, or --target-cell-id")
        if (selectorCount > 1)
            CMD_ERR("Only one target selector is allowed: --target-nci, --target-name, or --target-cell-id")

        return cmd;
    }
    else if (subCmd == "ho-status")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::HO_STATUS);
    }
    else if (subCmd == "ho-cancel")
    {
        auto cmd = std::make_unique<GnbCliCommand>(GnbCliCommand::HO_CANCEL);
        if (options.positionalCount() == 0)
            CMD_ERR("UE ID is expected")
        if (options.positionalCount() > 1)
            CMD_ERR("Only one UE ID is expected")
        cmd->ueId = utils::ParseInt(options.getPositional(0));
        if (cmd->ueId <= 0)
            CMD_ERR("Invalid UE ID")
        return cmd;
    }
    else if (subCmd == "xn-peers")
    {
        return std::make_unique<GnbCliCommand>(GnbCliCommand::XN_PEERS);
    }

    return nullptr;
}

static std::unique_ptr<UeCliCommand> UeCliParseImpl(const std::string &subCmd, const opt::OptionsResult &options,
                                                    std::string &error)
{
    if (subCmd == "info")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::INFO);
    }
    else if (subCmd == "status")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::STATUS);
    }
    else if (subCmd == "timers")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::TIMERS);
    }
    else if (subCmd == "deregister")
    {
        auto cmd = std::make_unique<UeCliCommand>(UeCliCommand::DE_REGISTER);
        if (options.positionalCount() == 0)
            CMD_ERR("De-registration type is expected")
        if (options.positionalCount() > 1)
            CMD_ERR("Only one de-registration type is expected")
        auto type = options.getPositional(0);
        if (type == "normal")
            cmd->deregCause = EDeregCause::NORMAL;
        else if (type == "switch-off")
            cmd->deregCause = EDeregCause::SWITCH_OFF;
        else if (type == "disable-5g")
            cmd->deregCause = EDeregCause::DISABLE_5G;
        else if (type == "remove-sim")
            cmd->deregCause = EDeregCause::USIM_REMOVAL;
        else
            CMD_ERR("Invalid de-registration type, possible values are: \"normal\", \"disable-5g\", \"switch-off\", "
                    "\"remove-sim\"")
        return cmd;
    }
    else if (subCmd == "ps-release")
    {
        auto cmd = std::make_unique<UeCliCommand>(UeCliCommand::PS_RELEASE);
        if (options.positionalCount() == 0)
            CMD_ERR("At least one PDU session ID is expected")
        if (options.positionalCount() > 15)
            CMD_ERR("Too many PDU session IDs")
        cmd->psCount = options.positionalCount();
        for (int i = 0; i < cmd->psCount; i++)
        {
            int n = 0;
            if (!utils::TryParseInt(options.getPositional(i), n))
                CMD_ERR("Invalid PDU session ID value")
            if (n <= 0)
                CMD_ERR("PDU session IDs must be positive integer")
            if (n > 15)
                CMD_ERR("PDU session IDs cannot be greater than 15")
            cmd->psIds[i] = static_cast<int8_t>(n);
        }
        return cmd;
    }
    else if (subCmd == "ps-release-all")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::PS_RELEASE_ALL);
    }
    else if (subCmd == "ps-establish")
    {
        auto normalize = [](std::string s) {
            for (auto &c : s)
            {
                if (c >= 'a' && c <= 'z')
                    c = static_cast<char>(c - 'a' + 'A');
            }
            return s;
        };

        auto cmd = std::make_unique<UeCliCommand>(UeCliCommand::PS_ESTABLISH);
        if (options.positionalCount() == 0)
            CMD_ERR("PDU session type is expected")
        if (options.positionalCount() > 15)
            CMD_ERR("Only one PDU session type is expected")

        std::string type = normalize(options.getPositional(0));
        if (type == "IPV4")
            cmd->psType = nas::EPduSessionType::IPV4;
        else if (type == "IPV6")
            cmd->psType = nas::EPduSessionType::IPV6;
        else if (type == "IPV4V6")
            cmd->psType = nas::EPduSessionType::IPV4V6;
        else
            CMD_ERR("Invalid PDU session type, possible values are: \"IPv4\", \"IPv6\", \"IPv4v6\"")

        cmd->isEmergency = options.hasFlag('e', "emergency");
        if (cmd->isEmergency)
        {
            if (options.hasFlag(std::nullopt, "sst") || options.hasFlag(std::nullopt, "sd") ||
                options.hasFlag('n', "dnn"))
                CMD_ERR("SST, SD, and DNN parameters cannot be used for emergency PDU sessions")
        }
        if (options.hasFlag('n', "dnn"))
            cmd->apn = options.getOption('n', "dnn");
        if (options.hasFlag(std::nullopt, "sd") && !options.hasFlag(std::nullopt, "sst"))
            CMD_ERR("SST is also required in case of an SD is provided")
        if (options.hasFlag(std::nullopt, "sst"))
        {
            int n = 0;
            if (!utils::TryParseInt(options.getOption(std::nullopt, "sst"), n) || n <= 0 || n >= 256)
                CMD_ERR("Invalid SST value")
            cmd->sNssai = SingleSlice{};
            cmd->sNssai->sst = static_cast<uint8_t>(n);

            if (options.hasFlag(std::nullopt, "sd"))
            {
                if (!utils::TryParseInt(options.getOption(std::nullopt, "sd"), n) || n <= 0 || n > 0xFFFFFF)
                    CMD_ERR("Invalid SD value")
                cmd->sNssai->sd = octet3{n};
            }
        }
        return cmd;
    }
    else if (subCmd == "ps-modify")
    {
        auto parseQfiList = [](const std::string &input, std::vector<uint8_t> &output, bool allowZero) -> bool {
            std::stringstream ss{input};
            std::string token;
            while (std::getline(ss, token, ','))
            {
                utils::Trim(token);
                if (token.empty())
                    return false;

                int qfi = 0;
                if (!utils::TryParseInt(token, qfi) || qfi < (allowZero ? 0 : 1) || qfi > 63)
                    return false;

                auto value = static_cast<uint8_t>(qfi);
                if (std::find(output.begin(), output.end(), value) == output.end())
                    output.push_back(value);
            }
            return !output.empty();
        };

        auto trim0x = [](const std::string &s) {
            if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                return s.substr(2);
            return s;
        };
        auto isValidHex = [](const std::string &value) {
            if (value.empty() || (value.size() % 2) != 0)
                return false;
            return std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
        };

        auto cmd = std::make_unique<UeCliCommand>(UeCliCommand::PS_MODIFY);
        if (options.positionalCount() == 0)
            CMD_ERR("PDU session ID is expected")
        if (options.positionalCount() > 1)
            CMD_ERR("Only one PDU session ID is expected")

        int psi = 0;
        if (!utils::TryParseInt(options.getPositional(0), psi) || psi <= 0 || psi > 15)
            CMD_ERR("Invalid PDU session ID")
        cmd->psId = psi;

        if (options.hasFlag(std::nullopt, "qos-rules"))
        {
            auto hex = trim0x(options.getOption(std::nullopt, "qos-rules"));
            if (!isValidHex(hex))
                CMD_ERR("Invalid --qos-rules value, expected even-length hex string")
            cmd->psModifyQosRules = hex;
        }

        if (options.hasFlag(std::nullopt, "qos-flows"))
        {
            auto hex = trim0x(options.getOption(std::nullopt, "qos-flows"));
            if (!isValidHex(hex))
                CMD_ERR("Invalid --qos-flows value, expected even-length hex string")
            cmd->psModifyQosFlows = hex;
        }

        bool hasFlowOp = options.hasFlag(std::nullopt, "flow-op");
        bool hasFlowQfi = options.hasFlag(std::nullopt, "flow-qfi");
        if (hasFlowOp != hasFlowQfi)
            CMD_ERR("Both --flow-op and --flow-qfi are required together")

        if (!hasFlowOp && (options.hasFlag(std::nullopt, "flow-mode") || options.hasFlag(std::nullopt, "flow-5qi")))
            CMD_ERR("--flow-mode and --flow-5qi can only be used together with --flow-op")

        if (hasFlowOp && cmd->psModifyQosFlows.has_value())
            CMD_ERR("Do not combine --qos-flows with --flow-op/--flow-qfi")

        if (hasFlowOp)
        {
            std::string op = options.getOption(std::nullopt, "flow-op");
            std::transform(op.begin(), op.end(), op.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            bool allowQfiZero = false;
            if (op == "modify")
                cmd->psModifyFlowOp = nas::EQoSOperationCode::MODIFY_EXISTING;
            else if (op == "create" || op == "add")
            {
                cmd->psModifyFlowOp = nas::EQoSOperationCode::CREATE_NEW;
                allowQfiZero = true;
            }
            else if (op == "delete" || op == "remove")
                cmd->psModifyFlowOp = nas::EQoSOperationCode::DELETE_EXISTING;
            else
                CMD_ERR("Invalid --flow-op value, possible values are: modify, create, delete")

            if (!parseQfiList(options.getOption(std::nullopt, "flow-qfi"), cmd->psModifyFlowQfis, allowQfiZero))
                CMD_ERR("Invalid --flow-qfi value, expected comma-separated QFI list in range [1,63], or 0 for create")

            if (cmd->psModifyFlowOp != nas::EQoSOperationCode::CREATE_NEW)
            {
                if (std::any_of(cmd->psModifyFlowQfis.begin(), cmd->psModifyFlowQfis.end(),
                                [](uint8_t qfi) { return qfi == 0; }))
                {
                    CMD_ERR("QFI 0 is only allowed with --flow-op create")
                }
            }

            if (options.hasFlag(std::nullopt, "flow-mode"))
            {
                std::string mode = options.getOption(std::nullopt, "flow-mode");
                std::transform(mode.begin(), mode.end(), mode.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                if (cmd->psModifyFlowOp != nas::EQoSOperationCode::MODIFY_EXISTING)
                    CMD_ERR("--flow-mode is only valid with --flow-op modify")

                if (mode == "replace")
                    cmd->psModifyFlowReplacement = true;
                else if (mode == "extend")
                    cmd->psModifyFlowReplacement = false;
                else
                    CMD_ERR("Invalid --flow-mode value, possible values are: replace, extend")
            }

            if (options.hasFlag(std::nullopt, "flow-5qi"))
            {
                int v = 0;
                if (!utils::TryParseInt(options.getOption(std::nullopt, "flow-5qi"), v) || v < 1 || v > 254)
                    CMD_ERR("Invalid --flow-5qi value, expected integer in range [1,254]")
                cmd->psModifyFlow5qi = static_cast<uint8_t>(v);
            }

            if (cmd->psModifyFlowOp == nas::EQoSOperationCode::CREATE_NEW ||
                cmd->psModifyFlowOp == nas::EQoSOperationCode::MODIFY_EXISTING)
            {
                if (!cmd->psModifyFlow5qi.has_value())
                    CMD_ERR("TS 24.501 requires non-empty parameters for create/modify QoS flow; provide --flow-5qi")
            }
        }

        bool hasRuleOp = options.hasFlag(std::nullopt, "rule-op");
        bool hasRuleId = options.hasFlag(std::nullopt, "rule-id");

        bool hasRuleFields = hasRuleOp || hasRuleId || options.hasFlag(std::nullopt, "rule-qfi") ||
                             options.hasFlag(std::nullopt, "rule-precedence") ||
                             options.hasFlag(std::nullopt, "rule-dir") || options.hasFlag(std::nullopt, "rule-seg") ||
                             options.hasFlag(std::nullopt, "rule-remote-ipv4");

        if (hasRuleFields && cmd->psModifyQosRules.has_value())
            CMD_ERR("Do not combine --qos-rules with generated --rule-* options")

        if (hasRuleFields && !hasRuleOp)
            CMD_ERR("--rule-op is required when using any --rule-* option")

        if (hasRuleOp != hasRuleId)
            CMD_ERR("Both --rule-op and --rule-id are required together")

        if (hasRuleOp)
        {
            std::string op = options.getOption(std::nullopt, "rule-op");
            std::transform(op.begin(), op.end(), op.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (op == "create" || op == "add")
                cmd->psModifyRuleOp = EQoSRuleOperationCode::CREATE_NEW;
            else if (op == "delete" || op == "remove")
                cmd->psModifyRuleOp = EQoSRuleOperationCode::DELETE_EXISTING;
            else
                CMD_ERR("Invalid --rule-op value, possible values are: create, delete")

            int ruleId = 0;
            if (!utils::TryParseInt(options.getOption(std::nullopt, "rule-id"), ruleId) || ruleId < 0 || ruleId > 255)
                CMD_ERR("Invalid --rule-id value, expected integer in range [0,255]")
            cmd->psModifyRuleId = static_cast<uint8_t>(ruleId);

            if (*cmd->psModifyRuleOp == EQoSRuleOperationCode::CREATE_NEW)
            {
                if (ruleId != 0)
                    CMD_ERR("For --rule-op create, --rule-id must be 0 per TS 24.501 (no QoS rule identifier assigned)")

                if (!options.hasFlag(std::nullopt, "rule-precedence"))
                    CMD_ERR("--rule-precedence is required with --rule-op create")
                if (!options.hasFlag(std::nullopt, "rule-qfi"))
                    CMD_ERR("--rule-qfi is required with --rule-op create")

                int precedence = 0;
                if (!utils::TryParseInt(options.getOption(std::nullopt, "rule-precedence"), precedence) || precedence < 0 ||
                    precedence > 255 || precedence == 80)
                {
                    CMD_ERR("Invalid --rule-precedence value, expected integer in range [0,255] except 80")
                }
                cmd->psModifyRulePrecedence = static_cast<uint8_t>(precedence);

                int qfi = 0;
                if (!utils::TryParseInt(options.getOption(std::nullopt, "rule-qfi"), qfi) || qfi < 0 || qfi > 63)
                    CMD_ERR("Invalid --rule-qfi value, expected integer in range [0,63]")
                cmd->psModifyRuleQfi = static_cast<uint8_t>(qfi);

                cmd->psModifyRuleSegregation = true;
                if (options.hasFlag(std::nullopt, "rule-seg"))
                {
                    std::string seg = options.getOption(std::nullopt, "rule-seg");
                    std::transform(seg.begin(), seg.end(), seg.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    if (seg == "on" || seg == "true" || seg == "1")
                        cmd->psModifyRuleSegregation = true;
                    else if (seg == "off" || seg == "false" || seg == "0")
                        cmd->psModifyRuleSegregation = false;
                    else
                        CMD_ERR("Invalid --rule-seg value, possible values are: on, off")
                }

                cmd->psModifyRuleDirection = EQoSRuleDirection::BIDIRECTIONAL;
                if (options.hasFlag(std::nullopt, "rule-dir"))
                {
                    std::string dir = options.getOption(std::nullopt, "rule-dir");
                    std::transform(dir.begin(), dir.end(), dir.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    if (dir == "ul" || dir == "uplink")
                        cmd->psModifyRuleDirection = EQoSRuleDirection::UPLINK;
                    else if (dir == "dl" || dir == "downlink")
                        cmd->psModifyRuleDirection = EQoSRuleDirection::DOWNLINK;
                    else if (dir == "bi" || dir == "bidirectional")
                        cmd->psModifyRuleDirection = EQoSRuleDirection::BIDIRECTIONAL;
                    else
                        CMD_ERR("Invalid --rule-dir value, possible values are: ul, dl, bi")
                }

                if (options.hasFlag(std::nullopt, "rule-remote-ipv4"))
                {
                    std::string cidr = options.getOption(std::nullopt, "rule-remote-ipv4");
                    std::string ip = cidr;
                    int prefixLen = 32;

                    auto slashPos = cidr.find('/');
                    if (slashPos != std::string::npos)
                    {
                        ip = cidr.substr(0, slashPos);
                        int parsedPrefix = 0;
                        auto prefixStr = cidr.substr(slashPos + 1);
                        if (!utils::TryParseInt(prefixStr, parsedPrefix) || parsedPrefix < 0 || parsedPrefix > 32)
                            CMD_ERR("Invalid --rule-remote-ipv4 prefix, expected CIDR prefix in range [0,32]")
                        prefixLen = parsedPrefix;
                    }

                    in_addr addr{};
                    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
                        CMD_ERR("Invalid --rule-remote-ipv4 address, expected IPv4 or CIDR (e.g. 8.8.8.8/32)")

                    cmd->psModifyRuleRemoteIpv4 = ip + "/" + std::to_string(prefixLen);
                }
            }
            else
            {
                if (ruleId == 0)
                    CMD_ERR("For --rule-op delete, --rule-id must reference an existing rule (>0)")

                if (options.hasFlag(std::nullopt, "rule-qfi") || options.hasFlag(std::nullopt, "rule-precedence") ||
                    options.hasFlag(std::nullopt, "rule-dir") || options.hasFlag(std::nullopt, "rule-seg") ||
                    options.hasFlag(std::nullopt, "rule-remote-ipv4"))
                {
                    CMD_ERR("--rule-qfi, --rule-precedence, --rule-dir, --rule-seg, and --rule-remote-ipv4 are only valid with --rule-op create")
                }
            }
        }

        if (options.hasFlag(std::nullopt, "sm-cause"))
        {
            int cause = 0;
            if (!utils::TryParseInt(options.getOption(std::nullopt, "sm-cause"), cause) || cause < 0 || cause > 255)
                CMD_ERR("Invalid --sm-cause value, expected integer in range [0,255]")
            cmd->psModifySmCause = cause;
        }

        if (!cmd->psModifyQosRules.has_value() && !cmd->psModifyQosFlows.has_value() && !cmd->psModifyFlowOp.has_value() &&
            !cmd->psModifyRuleOp.has_value() && !cmd->psModifySmCause.has_value())
        {
            CMD_ERR("At least one option is required: --qos-rules, --qos-flows, --flow-op/--flow-qfi, --rule-op/--rule-id, "
                    "or --sm-cause")
        }

        return cmd;
    }
    else if (subCmd == "ps-list")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::PS_LIST);
    }
    else if (subCmd == "rls-state")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::RLS_STATE);
    }
    else if (subCmd == "coverage")
    {
        return std::make_unique<UeCliCommand>(UeCliCommand::COVERAGE);
    }

    return nullptr;
}

std::unique_ptr<GnbCliCommand> ParseGnbCliCommand(std::vector<std::string> &&tokens, std::string &error,
                                                  std::string &output)
{
    std::string subCmd{};
    auto options = ParseCliCommandCommon(g_gnbCmdEntries, std::move(tokens), error, output, subCmd);
    if (options.has_value())
        return GnbCliParseImpl(subCmd, *options, error);
    return nullptr;
}

std::unique_ptr<UeCliCommand> ParseUeCliCommand(std::vector<std::string> &&tokens, std::string &error,
                                                std::string &output)
{
    std::string subCmd{};
    auto options = ParseCliCommandCommon(g_ueCmdEntries, std::move(tokens), error, output, subCmd);
    if (options.has_value())
        return UeCliParseImpl(subCmd, *options, error);
    return nullptr;
}

} // namespace app
