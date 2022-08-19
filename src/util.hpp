#pragma once
#include "config_parser.hpp"
#include "types.hpp"

#include <netinet/ether.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <optional>
#include <sdbusplus/bus.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Network/EthernetInterface/server.hpp>

namespace phosphor
{
namespace network
{

using EthernetInterfaceIntf =
    sdbusplus::xyz::openbmc_project::Network::server::EthernetInterface;

constexpr auto IPV4_MIN_PREFIX_LENGTH = 1;
constexpr auto IPV4_MAX_PREFIX_LENGTH = 32;
constexpr auto IPV6_MAX_PREFIX_LENGTH = 128;
constexpr auto IPV4_PREFIX = "169.254";
constexpr auto IPV6_PREFIX = "fe80";

namespace mac_address
{

/** @brief gets the MAC address from the Inventory.
 *  @param[in] bus - DBUS Bus Object.
 *  @param[in] intfName - Interface name
 */
ether_addr getfromInventory(sdbusplus::bus_t& bus, const std::string& intfName);

/** @brief Converts the given mac address into byte form
 *  @param[in] str - The mac address in human readable form
 *  @returns A mac address in network byte order
 *  @throws std::runtime_error for bad mac
 */
ether_addr fromString(const char* str);
inline ether_addr fromString(const std::string& str)
{
    return fromString(str.c_str());
}

/** @brief Converts the given mac address bytes into a string
 *  @param[in] mac - The mac address
 *  @returns A valid mac address string
 */
std::string toString(const ether_addr& mac);

/** @brief Determines if the mac address is empty
 *  @param[in] mac - The mac address
 *  @return True if 00:00:00:00:00:00
 */
bool isEmpty(const ether_addr& mac);

/** @brief Determines if the mac address is a multicast address
 *  @param[in] mac - The mac address
 *  @return True if multicast bit is set
 */
bool isMulticast(const ether_addr& mac);

/** @brief Determines if the mac address is a unicast address
 *  @param[in] mac - The mac address
 *  @return True if not multicast or empty
 */
bool isUnicast(const ether_addr& mac);

} // namespace mac_address

constexpr auto networkdService = "systemd-networkd.service";
constexpr auto timeSynchdService = "systemd-timesyncd.service";

/* @brief converts the given subnet into prefix notation.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] mask - Subnet Mask.
 * @returns prefix.
 */
uint8_t toCidr(int addressFamily, const std::string& mask);

/* @brief converts a sockaddr for the specified address family into
 *        a type_safe InAddrAny.
 * @param[in] addressFamily - The address family of the buf
 * @param[in] buf - The network byte order address
 */
InAddrAny addrFromBuf(int addressFamily, std::string_view buf);

/* @brief converts the ip bytes into a string representation
 * @param[in] addr - input ip address to convert.
 * @returns String representation of the ip.
 */
std::string toString(const InAddrAny& addr);
std::string toString(const struct in_addr& addr);
std::string toString(const struct in6_addr& addr);

/* @brief converts the prefix into subnetmask.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] prefix - prefix length.
 * @returns subnet mask.
 */
std::string toMask(int addressFamily, uint8_t prefix);

/* @brief checks that the given ip address is link local or not.
 * @param[in] address - IP address.
 * @returns true if it is linklocal otherwise false.
 */
bool isLinkLocalIP(const std::string& address);

/* @brief checks that the given ip address valid or not.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] address - IP address.
 * @returns true if it is valid otherwise false.
 */
bool isValidIP(int addressFamily, const std::string& address);

/* @brief checks that the given prefix is valid or not.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] prefix - prefix length.
 * @returns true if it is valid otherwise false.
 */
bool isValidPrefix(int addressFamily, uint8_t prefixLength);

/** @brief Gets the map of interface and the associated
 *         address.
 *  @returns map of interface and the address.
 */
IntfAddrMap getInterfaceAddrs();

/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
InterfaceList getInterfaces();

/** @brief Delete the given interface.
 *  @param[in] intf - interface name.
 */
void deleteInterface(const std::string& intf);

/** @brief Converts the interface name into a u-boot environment
 *         variable that would hold its ethernet address.
 *
 *  @param[in] intf - interface name
 *  @return The name of th environment key
 */
std::optional<std::string> interfaceToUbootEthAddr(const char* intf);

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
DHCPVal getDHCPValue(const config::Parser& config);

/** @brief Read a boolean DHCP property from a conf file
 *  @param[in] config - The parsed configuration.
 *  @param[in] key - The property name.
 */
bool getDHCPProp(const config::Parser& config, std::string_view key);

namespace internal
{

/* @brief runs the given command in child process.
 * @param[in] path - path of the binary file which needs to be execeuted.
 * @param[in] args - arguments of the command.
 */
void executeCommandinChildProcess(const char* path, char** args);

/** @brief Get ignored interfaces from environment */
std::string_view getIgnoredInterfacesEnv();

/** @brief Parse the comma separated interface names */
std::set<std::string_view> parseInterfaces(std::string_view interfaces);

/** @brief Get the ignored interfaces */
const std::set<std::string_view>& getIgnoredInterfaces();

} // namespace internal

/* @brief runs the given command in child process.
 * @param[in] path -path of the binary file which needs to be execeuted.
 * @param[in] tArgs - arguments of the command.
 */
template <typename... ArgTypes>
void execute(const char* path, ArgTypes&&... tArgs)
{
    using expandType = char*[];

    expandType args = {const_cast<char*>(tArgs)..., nullptr};

    internal::executeCommandinChildProcess(path, args);
}

} // namespace network

} // namespace phosphor
