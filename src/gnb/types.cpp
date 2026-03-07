//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <sstream>

#include <gnb/types.hpp>
#include <utils/common.hpp>

namespace nr::gnb
{

Json ToJson(const GnbStatusInfo &v)
{
    return Json::Obj({{"is-ngap-up", v.isNgapUp}});
}

Json ToJson(const GnbConfig &v)
{
    std::string nciHex = "0x" + utils::IntToHex(static_cast<uint64_t>(v.nci));
    Json xnNeighbors = Json::Arr({});
    for (const auto &peer : v.xnNeighbors)
    {
        Json item = Json::Obj({
            {"name", peer.name},
            {"address", peer.address},
            {"port", peer.port},
        });
        if (peer.nci.has_value())
            item.put("nci", *peer.nci);
        xnNeighbors.push(std::move(item));
    }

    Json json = Json::Obj({
        {"name", v.name},
        {"nci", v.nci},
        {"nci-hex", nciHex},
        {"gnb-id", v.getGnbId()},
        {"gnb-id-length", v.gnbIdLength},
        {"cell-id", v.getCellId()},
        {"plmn", ToJson(v.plmn)},
        {"tac", v.tac},
        {"nssai", ToJson(v.nssai)},
        {"handover-policy",
         Json::Obj({
             {"default-mode", ToJson(v.handoverPolicy.defaultMode)},
             {"fallback-to-n2", v.handoverPolicy.fallbackToN2},
             {"require-same-amf-for-xn", v.handoverPolicy.requireSameAmfForXn},
         })},
        {"ngap-timers",
         Json::Obj({
             {"TNGRELOCprep", v.ngapTimers.tngRelocPrepMs},
             {"TNGRELOCoverall", v.ngapTimers.tngRelocOverallMs},
             {"preparedTtlMs", v.ngapTimers.preparedTtlMs},
             {"unmatchedCompleteTtlMs", v.ngapTimers.unmatchedCompleteTtlMs},
         })},
        {"ngap-ip", v.ngapIp},
        {"gtp-ip", v.gtpIp},
        {"xn-port", v.xnPort},
        {"xn-neighbors", xnNeighbors},
        {"paging-drx", ToJson(v.pagingDrx)},
        {"ignore-sctp-id", v.ignoreStreamIds},
    });

    if (v.allowedNrEncryptionAlgs || v.allowedNrIntegrityAlgs || v.allowedEutraEncryptionAlgs ||
        v.allowedEutraIntegrityAlgs)
    {
        Json security = Json::Obj({});
        if (v.allowedNrEncryptionAlgs)
            security.put("allowed-nr-encryption-algs",
                         "0x" + utils::IntToHex(static_cast<uint64_t>(v.allowedNrEncryptionAlgs.value())));
        if (v.allowedNrIntegrityAlgs)
            security.put("allowed-nr-integrity-algs",
                         "0x" + utils::IntToHex(static_cast<uint64_t>(v.allowedNrIntegrityAlgs.value())));
        if (v.allowedEutraEncryptionAlgs)
            security.put("allowed-eutra-encryption-algs",
                         "0x" + utils::IntToHex(static_cast<uint64_t>(v.allowedEutraEncryptionAlgs.value())));
        if (v.allowedEutraIntegrityAlgs)
            security.put("allowed-eutra-integrity-algs",
                         "0x" + utils::IntToHex(static_cast<uint64_t>(v.allowedEutraIntegrityAlgs.value())));

        json.put("security", security);
    }

    return json;
}

Json ToJson(const NgapAmfContext &v)
{
    auto isIp6 = utils::GetIpVersion(v.address) == 6;
    auto address = isIp6 ? "[" + v.address + "]" : v.address;

    return Json::Obj({
        {"id", v.ctxId},
        {"name", v.amfName},
        {"address", address + ":" + std::to_string(v.port)},
        {"state", ToJson(v.state).str()},
        {"capacity", v.relativeCapacity},
        {"association", ToJson(v.association)},
        {"served-guami", ::ToJson(v.servedGuamiList)},
        {"served-plmn", ::ToJson(v.plmnSupportList)},
    });
}

Json ToJson(const EAmfState &v)
{
    switch (v)
    {
    case EAmfState::NOT_CONNECTED:
        return "NOT_CONNECTED";
    case EAmfState::WAITING_NG_SETUP:
        return "WAITING_NG_SETUP";
    case EAmfState::CONNECTED:
        return "CONNECTED";
    default:
        return "?";
    }
}

Json ToJson(const EHandoverMode &v)
{
    switch (v)
    {
    case EHandoverMode::AUTO:
        return "auto";
    case EHandoverMode::N2:
        return "n2";
    case EHandoverMode::XN:
        return "xn";
    default:
        return "?";
    }
}

Json ToJson(const EPagingDrx &v)
{
    switch (v)
    {
    case EPagingDrx::V32:
        return "v32";
    case EPagingDrx::V64:
        return "v64";
    case EPagingDrx::V128:
        return "v128";
    case EPagingDrx::V256:
        return "v256";
    default:
        return "?";
    }
}

Json ToJson(const SctpAssociation &v)
{
    return Json::Obj({{"id", v.associationId}, {"rx-num", v.inStreams}, {"tx-num", v.outStreams}});
}

Json ToJson(const ServedGuami &v)
{
    return Json::Obj({{"guami", ToJson(v.guami)}, {"backup-amf", v.backupAmfName}});
}

Json ToJson(const Guami &v)
{
    return Json::Obj({
        {"plmn", ToJson(v.plmn)},
        {"region-id", ::ToJson(v.amfRegionId)},
        {"set-id", ::ToJson(v.amfSetId)},
        {"pointer", ::ToJson(v.amfPointer)},
    });
}

} // namespace nr::gnb
