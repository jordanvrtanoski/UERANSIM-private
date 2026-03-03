//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include <unistd.h>

#include <gnb/gnb.hpp>
#include <lib/app/base_app.hpp>
#include <lib/app/cli_base.hpp>
#include <lib/app/cli_cmd.hpp>
#include <lib/app/proc_table.hpp>
#include <utils/constants.hpp>
#include <utils/io.hpp>
#include <utils/options.hpp>
#include <utils/yaml_utils.hpp>
#include <yaml-cpp/yaml.h>

static app::CliServer *g_cliServer = nullptr;
static nr::gnb::GnbConfig *g_refConfig = nullptr;
static std::unordered_map<std::string, nr::gnb::GNodeB *> g_gnbMap{};
static app::CliResponseTask *g_cliRespTask = nullptr;

static struct Options
{
    std::string configFile{};
    bool disableCmd{};
} g_options{};

static nr::gnb::GnbConfig *ReadConfigYaml()
{
    auto *result = new nr::gnb::GnbConfig();
    auto config = YAML::LoadFile(g_options.configFile);

    result->plmn.mcc = yaml::GetInt32(config, "mcc", 1, 999);
    yaml::GetString(config, "mcc", 3, 3);
    result->plmn.mnc = yaml::GetInt32(config, "mnc", 0, 999);
    result->plmn.isLongMnc = yaml::GetString(config, "mnc", 2, 3).size() != 2;

    result->nci = yaml::GetInt64(config, "nci", 0, 0xFFFFFFFFFll);
    result->gnbIdLength = yaml::GetInt32(config, "idLength", 22, 32);
    result->tac = yaml::GetInt32(config, "tac", 0, 0xFFFFFF);

    result->linkIp = yaml::GetIpAddress(config, "linkIp");
    result->ngapIp = yaml::GetIpAddress(config, "ngapIp");
    result->gtpIp = yaml::GetIpAddress(config, "gtpIp");

    if (yaml::HasField(config, "gtpAdvertiseIp"))
        result->gtpAdvertiseIp = yaml::GetIpAddress(config, "gtpAdvertiseIp");

    result->ignoreStreamIds = yaml::GetBool(config, "ignoreStreamIds");
    result->pagingDrx = EPagingDrx::V128;
    result->name = "UERANSIM-gnb-" + std::to_string(result->plmn.mcc) + "-" + std::to_string(result->plmn.mnc) + "-" +
                   std::to_string(result->getGnbId()); // NOTE: Avoid using "/" dir separator character.

    for (auto &amfConfig : yaml::GetSequence(config, "amfConfigs"))
    {
        nr::gnb::GnbAmfConfig c{};
        c.address = yaml::GetIpAddress(amfConfig, "address");
        c.port = static_cast<uint16_t>(yaml::GetInt32(amfConfig, "port", 1024, 65535));
        result->amfConfigs.push_back(c);
    }

    for (auto &nssai : yaml::GetSequence(config, "slices"))
    {
        SingleSlice s{};
        s.sst = yaml::GetInt32(nssai, "sst", 0, 0xFF);
        if (yaml::HasField(nssai, "sd"))
            s.sd = octet3{yaml::GetInt32(nssai, "sd", 0, 0xFFFFFF)};
        result->nssai.slices.push_back(s);
    }

    if (yaml::HasField(config, "neighbors"))
    {
        for (auto &n : yaml::GetSequence(config, "neighbors"))
        {
            nr::gnb::GnbNeighborConfig nb{};

            nb.nci = yaml::GetInt64(n, "nci", 0, 0xFFFFFFFFFll);
            nb.gnbIdLength = yaml::HasField(n, "idLength") ? yaml::GetInt32(n, "idLength", 22, 32) : result->gnbIdLength;
            nb.tac = yaml::HasField(n, "tac") ? yaml::GetInt32(n, "tac", 0, 0xFFFFFF) : result->tac;

            nb.plmn.mcc = yaml::HasField(n, "mcc") ? yaml::GetInt32(n, "mcc", 1, 999) : result->plmn.mcc;
            if (yaml::HasField(n, "mcc"))
                yaml::GetString(n, "mcc", 3, 3);
            nb.plmn.mnc = yaml::HasField(n, "mnc") ? yaml::GetInt32(n, "mnc", 0, 999) : result->plmn.mnc;
            if (yaml::HasField(n, "mnc"))
                nb.plmn.isLongMnc = yaml::GetString(n, "mnc", 2, 3).size() != 2;
            else
                nb.plmn.isLongMnc = result->plmn.isLongMnc;

            if (yaml::HasField(n, "name"))
                nb.name = yaml::GetString(n, "name");
            else
                nb.name = "neighbor-" + std::to_string(nb.plmn.mcc) + "-" + std::to_string(nb.plmn.mnc) + "-" +
                          std::to_string(nb.getGnbId());

            result->neighbors.push_back(std::move(nb));
        }
    }

    if (yaml::HasField(config, "ngapTimers"))
    {
        auto t = config["ngapTimers"];

        if (t.Type() != YAML::NodeType::Map)
            throw std::runtime_error("Field 'ngapTimers' must be a map.");

        static const std::unordered_set<std::string> kAllowedKeys = {
            "TNGRELOCprep",
            "TNGRELOCoverall",
            "preparedTtlMs",
            "unmatchedCompleteTtlMs",
        };

        for (const auto &kv : t)
        {
            auto key = kv.first.as<std::string>();
            if (!kAllowedKeys.count(key))
                throw std::runtime_error("Field 'ngapTimers' has unknown key '" + key +
                                         "'. Allowed keys: TNGRELOCprep, TNGRELOCoverall, preparedTtlMs, "
                                         "unmatchedCompleteTtlMs.");
        }

        if (yaml::HasField(t, "TNGRELOCprep"))
            result->ngapTimers.tngRelocPrepMs = yaml::GetInt32(t, "TNGRELOCprep", 1, 600000);
        if (yaml::HasField(t, "TNGRELOCoverall"))
            result->ngapTimers.tngRelocOverallMs = yaml::GetInt32(t, "TNGRELOCoverall", 1, 600000);

        if (yaml::HasField(t, "preparedTtlMs"))
            result->ngapTimers.preparedTtlMs = yaml::GetInt32(t, "preparedTtlMs", 1, 600000);
        if (yaml::HasField(t, "unmatchedCompleteTtlMs"))
            result->ngapTimers.unmatchedCompleteTtlMs = yaml::GetInt32(t, "unmatchedCompleteTtlMs", 1, 600000);
    }

    return result;
}

static void ReadOptions(int argc, char **argv)
{
    opt::OptionsDescription desc{cons::Project,
                                 cons::Tag,
                                 "5G-SA gNB implementation",
                                 cons::Owner,
                                 "nr-gnb",
                                 {"-c <config-file> [option...]"},
                                 {},
                                 true,
                                 false};

    opt::OptionItem itemConfigFile = {'c', "config", "Use specified configuration file for gNB", "config-file"};
    opt::OptionItem itemDisableCmd = {'l', "disable-cmd", "Disable command line functionality for this instance",
                                      std::nullopt};

    desc.items.push_back(itemConfigFile);
    desc.items.push_back(itemDisableCmd);

    opt::OptionsResult opt{argc, argv, desc, false, nullptr};

    if (opt.hasFlag(itemDisableCmd))
        g_options.disableCmd = true;
    g_options.configFile = opt.getOption(itemConfigFile);

    try
    {
        g_refConfig = ReadConfigYaml();
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        exit(1);
    }
}

static void ReceiveCommand(app::CliMessage &msg)
{
    if (msg.value.empty())
    {
        g_cliServer->sendMessage(app::CliMessage::Result(msg.clientAddr, ""));
        return;
    }

    std::vector<std::string> tokens{};

    auto exp = opt::PerformExpansion(msg.value, tokens);
    if (exp != opt::ExpansionResult::SUCCESS)
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, "Invalid command: " + msg.value));
        return;
    }

    if (tokens.empty())
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, "Empty command"));
        return;
    }

    std::string error{}, output{};
    auto cmd = app::ParseGnbCliCommand(std::move(tokens), error, output);
    if (!error.empty())
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, error));
        return;
    }
    if (!output.empty())
    {
        g_cliServer->sendMessage(app::CliMessage::Result(msg.clientAddr, output));
        return;
    }
    if (cmd == nullptr)
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, ""));
        return;
    }

    if (g_gnbMap.count(msg.nodeName) == 0)
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, "Node not found: " + msg.nodeName));
        return;
    }

    auto *gnb = g_gnbMap[msg.nodeName];
    gnb->pushCommand(std::move(cmd), msg.clientAddr);
}

static void Loop()
{
    if (!g_cliServer)
    {
        ::pause();
        return;
    }

    auto msg = g_cliServer->receiveMessage();
    if (msg.type == app::CliMessage::Type::ECHO)
    {
        g_cliServer->sendMessage(msg);
        return;
    }

    if (msg.type != app::CliMessage::Type::COMMAND)
        return;

    if (msg.value.size() > 0xFFFF)
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, "Command is too large"));
        return;
    }

    if (msg.nodeName.size() > 0xFFFF)
    {
        g_cliServer->sendMessage(app::CliMessage::Error(msg.clientAddr, "Node name is too large"));
        return;
    }

    ReceiveCommand(msg);
}

int main(int argc, char **argv)
{
    app::Initialize();
    ReadOptions(argc, argv);

    std::cout << cons::Name << std::endl;

    if (!g_options.disableCmd)
    {
        g_cliServer = new app::CliServer{};
        g_cliRespTask = new app::CliResponseTask(g_cliServer);
    }

    auto *gnb = new nr::gnb::GNodeB(g_refConfig, nullptr, g_cliRespTask);
    g_gnbMap[g_refConfig->name] = gnb;

    if (!g_options.disableCmd)
    {
        app::CreateProcTable(g_gnbMap, g_cliServer->assignedAddress().getPort());
        g_cliRespTask->start();
    }

    gnb->start();

    while (true)
        Loop();
}
