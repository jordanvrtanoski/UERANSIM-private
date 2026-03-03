//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "ho_phase1.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

#include <utils/crc32.hpp>
#include <utils/octet_view.hpp>

namespace rls::ho1
{

static constexpr const char kMagic[] = "UERANSIM_HO1";
static constexpr const size_t kMagicLen = 12;

static void WriteU16BE(uint8_t *p, uint16_t v)
{
    p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

static void WriteU32BE(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

static uint16_t ReadU16BE(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

static uint32_t ReadU32BE(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

static uint32_t ComputeCrc32Zeroed(const OctetString &payload, size_t crcOffset)
{
    std::vector<uint8_t> tmp{payload.data(), payload.data() + payload.length()};
    if (crcOffset + 4 <= tmp.size())
        std::fill(tmp.begin() + static_cast<long>(crcOffset), tmp.begin() + static_cast<long>(crcOffset + 4), 0);
    return utils::Crc32(tmp.data(), tmp.size());
}

bool LooksLikeHo1(const OctetString &payload)
{
    if (payload.length() < static_cast<int>(kMinHeaderLen))
        return false;
    return std::memcmp(payload.data(), kMagic, kMagicLen) == 0;
}

OctetString Encode(const Message &msg)
{
    std::vector<uint8_t> out;
    out.resize(kMinHeaderLen);

    std::memcpy(out.data(), kMagic, kMagicLen);
    out[12] = msg.version;
    out[13] = static_cast<uint8_t>(msg.msgType);

    // header_len, total_len, crc32 filled later
    WriteU16BE(out.data() + 14, 0);
    WriteU32BE(out.data() + 16, 0);
    WriteU32BE(out.data() + 20, 0);

    WriteU16BE(out.data() + 24, static_cast<uint16_t>(msg.tlvs.size()));
    WriteU16BE(out.data() + 26, 0);

    for (const auto &tlv : msg.tlvs)
    {
        uint16_t len = static_cast<uint16_t>(tlv.value.length());
        size_t old = out.size();
        out.resize(old + 4 + len);
        WriteU16BE(out.data() + old, tlv.type);
        WriteU16BE(out.data() + old + 2, len);
        if (len > 0)
            std::memcpy(out.data() + old + 4, tlv.value.data(), len);
    }

    uint16_t headerLen = static_cast<uint16_t>(kMinHeaderLen);
    uint32_t totalLen = static_cast<uint32_t>(out.size());
    WriteU16BE(out.data() + 14, headerLen);
    WriteU32BE(out.data() + 16, totalLen);

    OctetString payload{std::move(out)};
    uint32_t crc = ComputeCrc32Zeroed(payload, 20);

    WriteU32BE(payload.data() + 20, crc);
    return payload;
}

DecodeResult Decode(const OctetString &payload)
{
    DecodeResult res{};

    if (payload.length() < static_cast<int>(kMinHeaderLen))
    {
        res.ok = false;
        res.reason = DecodeDropReason::BAD_LENGTH;
        res.error = "payload too short";
        return res;
    }

    if (std::memcmp(payload.data(), kMagic, kMagicLen) != 0)
    {
        res.ok = false;
        res.reason = DecodeDropReason::BAD_MAGIC;
        res.error = "bad magic";
        return res;
    }

    uint8_t version = payload.data()[12];
    uint8_t msgType = payload.data()[13];
    uint16_t headerLen = ReadU16BE(payload.data() + 14);
    uint32_t totalLen = ReadU32BE(payload.data() + 16);
    uint32_t crcWire = ReadU32BE(payload.data() + 20);
    uint16_t tlvCount = ReadU16BE(payload.data() + 24);

    if (version != kVersion)
    {
        res.ok = false;
        res.reason = DecodeDropReason::BAD_VERSION;
        res.error = "unsupported version";
        return res;
    }

    if (headerLen < kMinHeaderLen || totalLen != static_cast<uint32_t>(payload.length()) || headerLen > totalLen)
    {
        res.ok = false;
        res.reason = DecodeDropReason::BAD_LENGTH;
        res.error = "invalid header/length fields";
        return res;
    }

    uint32_t crcCalc = ComputeCrc32Zeroed(payload, 20);
    if (crcCalc != crcWire)
    {
        res.ok = false;
        res.reason = DecodeDropReason::BAD_CRC;
        res.error = "crc mismatch";
        return res;
    }

    MsgType mt = static_cast<MsgType>(msgType);
    if (mt != MsgType::HO_CMD && mt != MsgType::HO_COMPLETE && mt != MsgType::HO_FAIL && mt != MsgType::NGAP_SRC_TO_TGT &&
        mt != MsgType::NGAP_TGT_TO_SRC)
    {
        res.ok = false;
        res.reason = DecodeDropReason::UNKNOWN_TYPE;
        res.error = "unknown msg_type";
        return res;
    }

    Message msg{};
    msg.version = version;
    msg.msgType = mt;

    size_t index = kMinHeaderLen;
    for (uint16_t i = 0; i < tlvCount; i++)
    {
        if (index + 4 > static_cast<size_t>(payload.length()))
        {
            res.ok = false;
            res.reason = DecodeDropReason::MALFORMED_TLV;
            res.error = "tlv header truncated";
            return res;
        }

        uint16_t t = ReadU16BE(payload.data() + index);
        uint16_t l = ReadU16BE(payload.data() + index + 2);
        index += 4;

        if (index + l > static_cast<size_t>(payload.length()))
        {
            res.ok = false;
            res.reason = DecodeDropReason::MALFORMED_TLV;
            res.error = "tlv value truncated";
            return res;
        }

        OctetString v = OctetString::FromArray(payload.data() + index, l);
        index += l;

        msg.tlvs.push_back(Tlv{t, std::move(v)});
    }

    res.ok = true;
    res.reason = DecodeDropReason::NONE;
    res.message = std::move(msg);
    return res;
}

std::optional<OctetString> FindTlvBytes(const Message &msg, uint16_t type)
{
    for (const auto &t : msg.tlvs)
    {
        if (t.type == type)
            return t.value.copy();
    }
    return std::nullopt;
}

std::optional<std::string> FindTlvUtf8(const Message &msg, uint16_t type)
{
    auto v = FindTlvBytes(msg, type);
    if (!v.has_value())
        return std::nullopt;
    OctetView view{*v};
    return view.readUtf8String(v->length());
}

std::optional<uint32_t> FindTlvU32(const Message &msg, uint16_t type)
{
    auto v = FindTlvBytes(msg, type);
    if (!v.has_value() || v->length() != 4)
        return std::nullopt;
    return ReadU32BE(v->data());
}

std::optional<uint64_t> FindTlvU64(const Message &msg, uint16_t type)
{
    auto v = FindTlvBytes(msg, type);
    if (!v.has_value() || v->length() != 8)
        return std::nullopt;
    const uint8_t *p = v->data();
    uint64_t r = 0;
    for (int i = 0; i < 8; i++)
        r = (r << 8) | static_cast<uint64_t>(p[i]);
    return r;
}

} // namespace rls::ho1
