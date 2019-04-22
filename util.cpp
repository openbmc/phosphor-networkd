#include "util.hpp"

#include "config_parser.hpp"
#include "types.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/wait.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <experimental/filesystem>
#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;

InAddrAny addrFromBuf(int addressFamily, std::string_view buf)
{
    if (addressFamily == AF_INET)
    {
        struct in_addr ret;
        if (buf.size() != sizeof(ret))
        {
            throw std::runtime_error("Buf not in_addr sized");
        }
        memcpy(&ret, buf.data(), sizeof(ret));
        return ret;
    }
    else if (addressFamily == AF_INET6)
    {
        struct in6_addr ret;
        if (buf.size() != sizeof(ret))
        {
            throw std::runtime_error("Buf not in6_addr sized");
        }
        memcpy(&ret, buf.data(), sizeof(ret));
        return ret;
    }

    throw std::runtime_error("Unsupported address family");
}

std::string toString(const InAddrAny& addr)
{
    std::string ip;
    if (std::holds_alternative<struct in_addr>(addr))
    {
        const auto& v = std::get<struct in_addr>(addr);
        ip.resize(INET_ADDRSTRLEN);
        if (inet_ntop(AF_INET, &v, ip.data(), ip.size()) == NULL)
        {
            throw std::runtime_error("Failed to convert IP4 to string");
        }
    }
    else if (std::holds_alternative<struct in6_addr>(addr))
    {
        const auto& v = std::get<struct in6_addr>(addr);
        ip.resize(INET6_ADDRSTRLEN);
        if (inet_ntop(AF_INET6, &v, ip.data(), ip.size()) == NULL)
        {
            throw std::runtime_error("Failed to convert IP6 to string");
        }
    }
    else
    {
        throw std::runtime_error("Invalid addr type");
    }
    ip.resize(strlen(ip.c_str()));
    return ip;
}

bool isValidIP(int addressFamily, const std::string& address)
{
    unsigned char buf[sizeof(struct in6_addr)];

    return inet_pton(addressFamily, address.c_str(), buf) > 0;
}

bool isValidPrefix(int addressFamily, uint8_t prefixLength)
{
    if (addressFamily == AF_INET)
    {
        if (prefixLength < IPV4_MIN_PREFIX_LENGTH ||
            prefixLength > IPV4_MAX_PREFIX_LENGTH)
        {
            return false;
        }
    }

    if (addressFamily == AF_INET6)
    {
        if (prefixLength < IPV4_MIN_PREFIX_LENGTH ||
            prefixLength > IPV6_MAX_PREFIX_LENGTH)
        {
            return false;
        }
    }

    return true;
}

InterfaceList getInterfaces()
{
    InterfaceList interfaces{};
    struct ifaddrs* ifaddr = nullptr;

    // attempt to fill struct with ifaddrs
    if (getifaddrs(&ifaddr) == -1)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during the getifaddrs call",
                        entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }

    AddrPtr ifaddrPtr(ifaddr);
    ifaddr = nullptr;

    for (ifaddrs* ifa = ifaddrPtr.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        // walk interfaces
        // if loopback ignore
        if (ifa->ifa_flags & IFF_LOOPBACK)
        {
            continue;
        }
        interfaces.emplace(ifa->ifa_name);
    }
    return interfaces;
}

void deleteInterface(const std::string& intf)
{
    pid_t pid = fork();
    int status{};

    if (pid == 0)
    {

        execl("/sbin/ip", "ip", "link", "delete", "dev", intf.c_str(), nullptr);
        auto error = errno;
        log<level::ERR>("Couldn't delete the device", entry("ERRNO=%d", error),
                        entry("INTF=%s", intf.c_str()));
        elog<InternalFailure>();
    }
    else if (pid < 0)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during fork", entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            { /* Error other than EINTR */
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            log<level::ERR>("Unable to delete the interface",
                            entry("INTF=%s", intf.c_str()),
                            entry("STATUS=%d", status));
            elog<InternalFailure>();
        }
    }
}

std::optional<std::string> interfaceToUbootEthAddr(const char* intf)
{
    constexpr char ethPrefix[] = "eth";
    constexpr size_t ethPrefixLen = sizeof(ethPrefix) - 1;
    if (strncmp(ethPrefix, intf, ethPrefixLen) != 0)
    {
        return std::nullopt;
    }
    const auto intfSuffix = intf + ethPrefixLen;
    if (intfSuffix[0] == '\0')
    {
        return std::nullopt;
    }
    char* end;
    unsigned long idx = strtoul(intfSuffix, &end, 10);
    if (end[0] != '\0')
    {
        return std::nullopt;
    }
    if (idx == 0)
    {
        return "ethaddr";
    }
    return "eth" + std::to_string(idx) + "addr";
}

bool getDHCPValue(const std::string& confDir, const std::string& intf)
{
    bool dhcp = false;
    // Get the interface mode value from systemd conf
    // using namespace std::string_literals;
    fs::path confPath = confDir;
    std::string fileName = systemd::config::networkFilePrefix + intf +
                           systemd::config::networkFileSuffix;
    confPath /= fileName;

    auto rc = config::ReturnCode::SUCCESS;
    config::ValueList values;
    config::Parser parser(confPath.string());

    std::tie(rc, values) = parser.getValues("Network", "DHCP");
    if (rc != config::ReturnCode::SUCCESS)
    {
        log<level::DEBUG>("Unable to get the value for Network[DHCP]",
                          entry("RC=%d", rc));
        return dhcp;
    }
    // There will be only single value for DHCP key.
    if (values[0] == "true")
    {
        dhcp = true;
    }
    return dhcp;
}

namespace internal
{

void executeCommandinChildProcess(const char* path, char** args)
{
    using namespace std::string_literals;
    pid_t pid = fork();
    int status{};

    if (pid == 0)
    {
        execv(path, args);
        auto error = errno;
        // create the command from var args.
        std::string command = path + " "s;

        for (int i = 0; args[i]; i++)
        {
            command += args[i] + " "s;
        }

        log<level::ERR>("Couldn't exceute the command",
                        entry("ERRNO=%d", error),
                        entry("CMD=%s", command.c_str()));
        elog<InternalFailure>();
    }
    else if (pid < 0)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during fork", entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }
    else if (pid > 0)
    {
        while (waitpid(pid, &status, 0) == -1)
        {
            if (errno != EINTR)
            { // Error other than EINTR
                status = -1;
                break;
            }
        }

        if (status < 0)
        {
            std::string command = path + " "s;
            for (int i = 0; args[i]; i++)
            {
                command += args[i] + " "s;
            }

            log<level::ERR>("Unable to execute the command",
                            entry("CMD=%s", command.c_str()),
                            entry("STATUS=%d", status));
            elog<InternalFailure>();
        }
    }
}
} // namespace internal

namespace mac_address
{

ether_addr fromString(const char* str)
{
    struct ether_addr* mac = ether_aton(str);
    if (mac == nullptr)
    {
        throw std::runtime_error("Invalid mac address string");
    }
    return *mac;
}

std::string toString(const ether_addr& mac)
{
    return ether_ntoa(&mac);
}

bool isEmpty(const ether_addr& mac)
{
    return equal(mac, ether_addr{});
}

bool isMulticast(const ether_addr& mac)
{
    return mac.ether_addr_octet[0] & 0b1;
}

bool isUnicast(const ether_addr& mac)
{
    return !isEmpty(mac) && !isMulticast(mac);
}

} // namespace mac_address
} // namespace network
} // namespace phosphor
