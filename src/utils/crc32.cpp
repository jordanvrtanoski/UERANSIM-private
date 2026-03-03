//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "crc32.hpp"

#include <array>

namespace
{

uint32_t Crc32TableValue(uint32_t index)
{
    uint32_t c = index;
    for (int i = 0; i < 8; i++)
        c = (c & 1U) ? (0xEDB88320U ^ (c >> 1U)) : (c >> 1U);
    return c;
}

const uint32_t *Crc32Table()
{
    static const auto table = []() {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; i++)
            t[i] = Crc32TableValue(i);
        return t;
    }();
    return table.data();
}

} // namespace

uint32_t utils::Crc32(const uint8_t *data, size_t len)
{
    const uint32_t *table = Crc32Table();
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ data[i]) & 0xFFU] ^ (crc >> 8U);
    return crc ^ 0xFFFFFFFFU;
}
