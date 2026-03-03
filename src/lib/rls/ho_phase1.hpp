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
#include <string>
#include <vector>

#include <utils/octet_string.hpp>

namespace rls::ho1
{

static constexpr const uint8_t kVersion = 0x01;
static constexpr const size_t kMinHeaderLen = 28;

enum class MsgType : uint8_t
{
    HO_CMD = 0x01,
    HO_COMPLETE = 0x02,
    HO_FAIL = 0x03,

    NGAP_SRC_TO_TGT = 0x11,
    NGAP_TGT_TO_SRC = 0x12,
};

enum class DecodeDropReason
{
    NONE = 0,
    BAD_MAGIC,
    BAD_VERSION,
    BAD_LENGTH,
    BAD_CRC,
    UNKNOWN_TYPE,
    MALFORMED_TLV,
};

struct Tlv
{
    uint16_t type{};
    OctetString value{};
};

struct Message
{
    uint8_t version{kVersion};
    MsgType msgType{MsgType::HO_CMD};
    std::vector<Tlv> tlvs{};
};

struct DecodeResult
{
    bool ok{};
    DecodeDropReason reason{DecodeDropReason::NONE};
    std::string error{};
    Message message{};
};

namespace tlv
{
static constexpr const uint16_t token = 0x0001;
static constexpr const uint16_t ue_id_hint = 0x0002;
static constexpr const uint16_t attempt_id = 0x0003;
static constexpr const uint16_t timestamp_ms = 0x0004;
static constexpr const uint16_t ue_sti = 0x0005;

static constexpr const uint16_t target_cell_id = 0x0101;
static constexpr const uint16_t target_nci = 0x0102;
static constexpr const uint16_t target_name = 0x0103;
static constexpr const uint16_t target_link_ip = 0x0104;

static constexpr const uint16_t reason_code = 0x0201;
static constexpr const uint16_t reason_detail = 0x0202;
} // namespace tlv

bool LooksLikeHo1(const OctetString &payload);

OctetString Encode(const Message &msg);
DecodeResult Decode(const OctetString &payload);

std::optional<OctetString> FindTlvBytes(const Message &msg, uint16_t type);
std::optional<std::string> FindTlvUtf8(const Message &msg, uint16_t type);
std::optional<uint32_t> FindTlvU32(const Message &msg, uint16_t type);
std::optional<uint64_t> FindTlvU64(const Message &msg, uint16_t type);

} // namespace rls::ho1

