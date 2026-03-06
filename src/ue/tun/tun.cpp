//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "tun.hpp"
#include "config.hpp"
#include <utils/libc_error.hpp>

namespace nr::ue::tun
{

int TunAllocate(const char *namePrefix, std::string &allocatedName, std::string &error)
{
    int fd;
    char *name = nullptr;
    try
    {
        fd = tun::AllocateTun(namePrefix, &name);
        allocatedName = std::string{name};
    }
    catch (const LibError &e)
    {
        error = e.what();
        allocatedName = "";
        return 0;
    }

    return fd;
}

bool TunConfigure(const std::string &tunName, const std::string &ipAddress, const std::string &netmask, int mtu, bool configureRouting, std::string &error)
{
    try
    {
        tun::ConfigureTun(tunName.c_str(), ipAddress.c_str(), netmask.c_str(), mtu, configureRouting);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

bool TunConfigure6(const std::string &tunName, const std::string &ipv6Address, int ipv6Prefix, int mtu, bool configureRouting,
                   std::string &error)
{
    try
    {
        tun::ConfigureTun6(tunName.c_str(), ipv6Address.c_str(), ipv6Prefix, mtu, configureRouting);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

bool TunQueryIpv6Status(const std::string &tunName, bool &hasGlobalAddress, bool &hasDefaultRoute, std::string &error)
{
    try
    {
        tun::QueryIpv6Status(tunName.c_str(), hasGlobalAddress, hasDefaultRoute);
    }
    catch (const LibError &e)
    {
        error = e.what();
        return false;
    }

    return true;
}

} // namespace nr::ue::tun
