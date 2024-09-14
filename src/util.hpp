#pragma once
#include "types.hpp"

#include <stdplus/raw.hpp>
#include <stdplus/zstring_view.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace phosphor
{
namespace network
{
namespace config
{
class Parser;
}

/* @brief converts a sockaddr for the specified address family into
 *        a type_safe InAddrAny.
 * @param[in] family - The address family of the buf
 * @param[in] buf - The network byte order address
 */
constexpr stdplus::InAnyAddr addrFromBuf(int family, std::string_view buf)
{
    switch (family)
    {
        case AF_INET:
            return stdplus::raw::copyFromStrict<stdplus::In4Addr>(buf);
        case AF_INET6:
            return stdplus::raw::copyFromStrict<stdplus::In6Addr>(buf);
    }
    throw std::invalid_argument("Unrecognized family");
}

/** @brief Converts the interface name into a u-boot environment
 *         variable that would hold its ethernet address.
 *
 *  @param[in] intf - interface name
 *  @return The name of th environment key
 */
std::optional<std::string> interfaceToUbootEthAddr(std::string_view intf);

/** @brief read the IPv6AcceptRA value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
bool getIPv6AcceptRA(const config::Parser& config);

/** @brief read the DHCP value from the configuration file
 *  @param[in] config - The parsed configuration.
 */
struct DHCPVal
{
    bool v4, v6;
};

enum class DHCPType
{
    v4,
    v6
};

DHCPVal getDHCPValue(const config::Parser& config);

/** @brief Read a boolean DHCP property from a conf file
 *  @param[in] config - The parsed configuration.
 *  @param[in] nwType - The network type.
 *  @param[in] key - The property name.
 */
bool getDHCPProp(const config::Parser& config, DHCPType dhcpType,
                 std::string_view key);

/** @brief Set IPv4 address last octet to zero
 *  @param[in] ip - IPv4 address
 */
std::string setIPv4AddressLastOctetToZero(const std::string& ip);

namespace internal
{

/* @brief runs the given command in child process.
 * @param[in] path - path of the binary file which needs to be execeuted.
 * @param[in] args - arguments of the command.
 */
void executeCommandinChildProcess(stdplus::zstring_view path, char** args);

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv();

/** @brief Parse the comma separated interface names */
std::unordered_set<std::string_view>
    parseInterfaces(std::string_view interfaces);

/** @brief Get the ignored interfaces */
const std::unordered_set<std::string_view>& getIgnoredInterfaces();

} // namespace internal

/* @brief runs the given command in child process.
 * @param[in] path -path of the binary file which needs to be execeuted.
 * @param[in] tArgs - arguments of the command.
 */
template <typename... ArgTypes>
void execute(stdplus::zstring_view path, ArgTypes&&... tArgs)
{
    using expandType = char*[];

    expandType args = {const_cast<char*>(tArgs)..., nullptr};

    internal::executeCommandinChildProcess(path, args);
}

} // namespace network

} // namespace phosphor
