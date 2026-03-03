//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstddef>
#include <cstdint>

namespace utils
{

uint32_t Crc32(const uint8_t *data, size_t len);

} // namespace utils

