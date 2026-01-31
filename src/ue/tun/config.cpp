//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "config.hpp"

#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_tun.h>
#include <memory>
#include <mutex>
#include <net/if.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include <utils/libc_error.hpp>

#define ROUTING_TABLE_PREFIX "rt_"
#define MAX_INTERFACE_COUNT 1024

static std::mutex configMutex;

static int ExecOutput(const char *cmd, std::string &output)
{
    char buffer[128];
    std::string result;
    std::string wrapped = "{ " + std::string(cmd) + "; } 2>&1";
    FILE *pipe = popen(wrapped.c_str(), "r");
    if (!pipe)
    {
        output = "popen() failed!";
        return -1;
    }
    try
    {
        while (fgets(buffer, sizeof buffer, pipe) != nullptr)
            result += buffer;
    }
    catch (...)
    {
        pclose(pipe);
        output = "";
        return -1;
    }
    output = result;

    int status = pclose(pipe);
    return WEXITSTATUS(status);
}

static std::string ExecStrict(const std::string &cmd)
{
    std::string output;
    if (ExecOutput(cmd.c_str(), output))
    {
        throw LibError("Command execution failed. The command was: " + cmd + ". The output is: '" + output +
                       "Command execution failure");
    }
    return output;
}

static void ExecBestEffort(const std::string &cmd)
{
    std::string output;
    (void)ExecOutput(cmd.c_str(), output);
}

static const char *NextInterfaceName(const std::string &prefix)
{
    std::set<std::string> names;

    struct ifaddrs *addrs, *tmp;

    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp)
    {
        std::string name = tmp->ifa_name;
        if (name.rfind(prefix, 0) == 0)
            names.insert(name);
        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);

    for (int i = 0; i < MAX_INTERFACE_COUNT; i++)
    {
        std::string name = prefix + std::to_string(i);
        if (!names.count(name))
            return strdup(name.c_str());
    }
    return nullptr;
}

static void TunSetIpAndUp(const char *ifName, const char *ipAddr, const char *netmask, int mtu)
{
    auto netmaskToPrefix = [](const char *mask) -> int {
        if (mask == nullptr || *mask == '\0')
            throw LibError("Invalid IPv4 netmask", EINVAL);

        bool isDotted = false;
        for (const char *p = mask; *p; ++p)
        {
            if (*p == '.')
            {
                isDotted = true;
                break;
            }
        }

        if (!isDotted)
        {
            char *end = nullptr;
            long v = strtol(mask, &end, 10);
            if (end == mask || *end != '\0' || v < 0 || v > 32)
                throw LibError(std::string("Invalid IPv4 prefix length: ") + mask, EINVAL);
            return static_cast<int>(v);
        }

        in_addr a{};
        if (inet_pton(AF_INET, mask, &a) != 1)
            throw LibError(std::string("Invalid IPv4 netmask: ") + mask, EINVAL);

        uint32_t m = ntohl(a.s_addr);
        int prefix = 0;
        while (prefix < 32 && (m & (1u << (31 - prefix))))
            ++prefix;
        if ((m << prefix) != 0)
            throw LibError(std::string("Non-contiguous IPv4 netmask: ") + mask, EINVAL);
        return prefix;
    };

    int prefix = netmaskToPrefix(netmask);

    // Use `ip` for IPv4 configuration (instead of ioctl) to behave consistently across kernels and VRF setups.
    ExecBestEffort("ip -4 addr flush dev " + std::string(ifName));
    ExecStrict("ip -4 addr replace " + std::string(ipAddr) + "/" + std::to_string(prefix) + " dev " +
               std::string(ifName));
    ExecStrict("ip link set dev " + std::string(ifName) + " mtu " + std::to_string(mtu));
    ExecStrict("ip link set dev " + std::string(ifName) + " up");
}

static void TunSetIpv6AndUp(const std::string &ifName, const std::string &ipv6Addr, int ipv6Prefix, int mtu)
{
    // Prevent the kernel from auto-generating its own link-local address for this interface.
    // Open5GS validates the IPv6 link-local Interface Identifier (IID) against the NAS-provided IID; if the host uses a
    // different auto-generated fe80::, Router Solicitations may be dropped as spoofing.
    ExecBestEffort("sysctl -q -w net.ipv6.conf." + ifName + ".disable_ipv6=0");
    ExecBestEffort("sysctl -q -w net.ipv6.conf." + ifName + ".addr_gen_mode=1");

    // Ensure there is no competing link-local address (new TUN interfaces often get an automatic fe80:: address on UP).
    ExecBestEffort("ip -6 addr flush dev " + ifName + " scope link");

    // Idempotent: replace (adds if missing) without noisy errors.
    ExecStrict("ip -6 addr replace " + ipv6Addr + "/" + std::to_string(ipv6Prefix) + " dev " + ifName);
    ExecStrict("ip link set dev " + ifName + " mtu " + std::to_string(mtu));
    ExecStrict("ip link set dev " + ifName + " up");
}

static std::string VrfNameForInterface(const std::string &ifName)
{
    // Keep within IFNAMSIZ (16 including NUL). UE tun names are <= 12 by config validation, so "vrf" + ifName fits.
    std::string vrf = "vrf" + ifName;
    if (vrf.size() >= IFNAMSIZ)
        vrf.resize(IFNAMSIZ - 1);
    return vrf;
}

static int VrfTableForInterface(const std::string &ifName)
{
    // Derive a stable per-interface routing table ID without touching /etc/iproute2/rt_tables.
    unsigned ifIndex = if_nametoindex(ifName.c_str());
    if (ifIndex == 0)
        throw LibError("if_nametoindex() failed for " + ifName, errno);

    // Pick a high range to avoid clashing with typical system tables.
    return 10000 + static_cast<int>(ifIndex);
}

static void EnsureVrfAttached(const std::string &ifName, int tableId)
{
    std::string vrfName = VrfNameForInterface(ifName);

    bool needCreate = true;
    {
        std::string output;
        // `ip` prints "Device does not exist" to stderr when the VRF hasn't been created yet. Suppress to keep logs clean.
        int rc = ExecOutput(("ip -d link show dev " + vrfName + " 2>/dev/null").c_str(), output);
        if (rc == 0)
        {
            int existingTable = -1;
            auto pos = output.find("table ");
            if (pos != std::string::npos && sscanf(output.c_str() + pos + 6, "%d", &existingTable) == 1 &&
                existingTable == tableId)
            {
                needCreate = false;
            }
            else
            {
                // Leftover VRF from a previous run with a different table ID. Detach and recreate.
                ExecBestEffort("ip link set dev " + ifName + " nomaster");
                ExecBestEffort("ip link del " + vrfName);
            }
        }
    }

    if (needCreate)
        ExecStrict("ip link add " + vrfName + " type vrf table " + std::to_string(tableId));

    ExecBestEffort("ip link set dev " + vrfName + " up");

    // Attach the interface to the VRF. This keeps per-UE/PDU routes isolated from the host.
    ExecStrict("ip link set dev " + ifName + " master " + vrfName);
}

namespace nr::ue::tun
{

int AllocateTun(const char *ifPrefix, char **allocatedName)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    const char *ifName = NextInterfaceName(ifPrefix);
    if (!ifName)
        throw LibError("TUN interface name could not be allocated.", errno);

    char tunName[IFNAMSIZ];
    strcpy(tunName, ifName);

    ifreq ifr{};
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        throw LibError("Open failure /dev/net/tun");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, tunName, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        close(fd);
        throw LibError("ioctl(TUNSETIFF)", errno);
    }

    strcpy(tunName, ifr.ifr_name);
    if (strcmp(tunName, ifName) != 0)
        throw LibError("TUN interface name could not be allocated.");

    *allocatedName = strdup(tunName);
    return fd;
}

void ConfigureTun(const char *tunName, const char *ipAddr, const char *netmask, int mtu, bool configureRoute)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    int vrfTable = VrfTableForInterface(tunName);
    EnsureVrfAttached(tunName, vrfTable);

    TunSetIpAndUp(tunName, ipAddr, netmask, mtu);
    if (configureRoute)
    {
        // Keep default route only inside VRF's table. Traffic uses it when explicitly bound to this interface (e.g.
        // `ping -I <tun> ...` or SO_BINDTODEVICE), otherwise the host uses its own routing.
        ExecStrict("ip route replace default dev " + std::string(tunName) + " table " + std::to_string(vrfTable));
    }
}

void ConfigureTun6(const char *tunName, const char *ipv6Addr, int ipv6Prefix, int mtu, bool configureRoute)
{
    // acquire the configuration lock
    const std::lock_guard<std::mutex> lock(configMutex);

    int vrfTable = VrfTableForInterface(tunName);
    EnsureVrfAttached(tunName, vrfTable);

    TunSetIpv6AndUp(tunName, ipv6Addr, ipv6Prefix, mtu);

    // IPv6 autoconf/RA knobs. With VRF, any default route learned via RA stays in the VRF table and does not affect the
    // host's default routing.
    ExecBestEffort("sysctl -q -w net.ipv6.conf." + std::string(tunName) + ".disable_ipv6=0");
    ExecBestEffort("sysctl -q -w net.ipv6.conf." + std::string(tunName) + ".autoconf=1");
    ExecBestEffort("sysctl -q -w net.ipv6.conf." + std::string(tunName) + ".accept_ra=2");
    ExecBestEffort("sysctl -q -w net.ipv6.conf." + std::string(tunName) + ".accept_ra_defrtr=1");

    if (!configureRoute)
        return;

    // Do not force an IPv6 default route here: Open5GS uses RS/RA to provide prefix + default router (SLAAC), and we
    // want the kernel-learned route inside the VRF table.
    ExecBestEffort("ip -6 route del default table " + std::to_string(vrfTable) + " 2>/dev/null");
}

} // namespace nr::ue::tun
