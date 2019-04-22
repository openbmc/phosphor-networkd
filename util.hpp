#pragma once

#include "config.h"

#include "ethernet_interface.hpp"
#include "types.hpp"

#include <netinet/ether.h>
#include <netinet/in.h>
#include <unistd.h>

#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace phosphor
{
namespace network
{

namespace mac_address
{

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

template <int family>
struct FamilyTraits
{
};

template <>
struct FamilyTraits<AF_INET>
{
    using addr = in_addr;
    static constexpr size_t strlen = INET_ADDRSTRLEN;
};

template <>
struct FamilyTraits<AF_INET6>
{
    using addr = in6_addr;
    static constexpr size_t strlen = INET6_ADDRSTRLEN;
};

/* @brief converts a sockaddr for the specified address family into
 *        a type_safe InAddrAny.
 * @param[in] family - The address family of the buf
 * @param[in] buf - The network byte order address
 */
InAddrAny addrFromBuf(int family, std::string_view buf);

/* @brief converts the ip bytes into a string representation
 * @param[in] addr - input ip address to convert.
 * @returns String representation of the ip.
 */
std::string toString(const InAddrAny& addr);

/* @brief checks that the given ip address valid or not.
 * @param[in] family - IP address family(AF_INET/AF_INET6).
 * @param[in] address - IP address.
 * @returns true if it is valid otherwise false.
 */
bool isValidIP(int family, const std::string& address);
bool isValidIP(const std::string& address);

/* @brief checks that the given prefix is valid or not.
 * @param[in] family - IP address family(AF_INET/AF_INET6).
 * @param[in] prefix - prefix length.
 * @returns true if it is valid otherwise false.
 */
bool isValidPrefix(int family, uint8_t prefixLength);

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

/** @brief read the DHCP value from the configuration file
 *  @param[in] confDir - Network configuration directory.
 *  @param[in] intf - Interface name.
 */
bool getDHCPValue(const std::string& confDir, const std::string& intf);

namespace internal
{

/* @brief runs the given command in child process.
 * @param[in] path - path of the binary file which needs to be execeuted.
 * @param[in] args - arguments of the command.
 */
void executeCommandinChildProcess(const char* path, char** args);

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

class Descriptor
{
  private:
    /** default value */
    int fd = -1;

  public:
    Descriptor() = default;
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    Descriptor(Descriptor&&) = delete;
    Descriptor& operator=(Descriptor&&) = delete;

    explicit Descriptor(int fd) : fd(fd)
    {
    }

    /* @brief sets the internal file descriptor with the given descriptor
     *        and closes the old descriptor.
     * @param[in] descriptor - File/Socket descriptor.
     */
    void set(int descriptor)
    {
        // same descriptor given
        if (fd == descriptor)
        {
            return;
        }

        // close the old descriptor
        if (fd >= 0)
        {
            close(fd);
        }

        fd = descriptor;
    }

    ~Descriptor()
    {
        if (fd >= 0)
        {
            close(fd);
        }
    }

    int operator()() const
    {
        return fd;
    }
};

} // namespace phosphor
