#include "util.hpp"

#include "config_parser.hpp"
#include "netlink.hpp"
#include "types.hpp"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/wait.h>

#include <cstdlib>
#include <experimental/filesystem>
#include <optional>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
namespace fs = std::experimental::filesystem;

InAddrAny addrFromBuf(int family, std::string_view buf)
{
    if (family == AF_INET)
    {
        return copyFrom<in_addr>(buf, "Invalid IPv4 buffer");
    }
    else if (family == AF_INET6)
    {
        return copyFrom<in6_addr>(buf, "Invalid IPv6 buffer");
    }

    throw std::invalid_argument("Invalid addr family");
}

template <int family>
std::string toString(const typename FamilyTraits<family>::addr& addr)
{
    char ret[FamilyTraits<family>::strlen];
    if (inet_ntop(family, &addr, ret, sizeof(ret)) == NULL)
    {
        throw std::runtime_error("Failed to convert IP to string");
    }
    return ret;
}

std::string toString(const InAddrAny& addr)
{
    if (std::holds_alternative<in_addr>(addr))
    {
        return toString<AF_INET>(std::get<in_addr>(addr));
    }
    else if (std::holds_alternative<in6_addr>(addr))
    {
        return toString<AF_INET6>(std::get<in6_addr>(addr));
    }

    throw std::invalid_argument("Invalid addr family");
}

template <int family>
bool isValidIP(const std::string& address)
{
    typename FamilyTraits<family>::addr addr;
    return inet_pton(family, address.c_str(), &addr) == 1;
}

bool isValidIP(int family, const std::string& address)
{
    if (family == AF_INET)
    {
        return isValidIP<AF_INET>(address);
    }
    else if (family == AF_INET6)
    {
        return isValidIP<AF_INET6>(address);
    }

    throw std::invalid_argument("Invalid addr family");
}

bool isValidIP(const std::string& address)
{
    return isValidIP<AF_INET>(address) || isValidIP<AF_INET6>(address);
}

template <int family>
bool isValidPrefix(uint8_t prefix)
{
    return prefix <= sizeof(typename FamilyTraits<family>::addr) * 8;
}

bool isValidPrefix(int family, uint8_t prefix)
{
    if (family == AF_INET)
    {
        return isValidPrefix<AF_INET>(prefix);
    }
    else if (family == AF_INET6)
    {
        return isValidPrefix<AF_INET6>(prefix);
    }

    throw std::invalid_argument("Invalid addr family");
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
