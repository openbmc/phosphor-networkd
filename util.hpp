#pragma once

#include "config.h"

#include "types.hpp"

#include <netinet/ether.h>
#include <unistd.h>

#include <cstring>
#include <sdbusplus/bus.hpp>
#include <string>
#include <string_view>

namespace phosphor
{
namespace network
{

constexpr auto IPV4_MIN_PREFIX_LENGTH = 1;
constexpr auto IPV4_MAX_PREFIX_LENGTH = 32;
constexpr auto IPV6_MAX_PREFIX_LENGTH = 64;
constexpr auto IPV4_PREFIX = "169.254";
constexpr auto IPV6_PREFIX = "fe80";

namespace mac_address
{

/** @brief gets the MAC address from the Inventory.
 *  @param[in] bus - DBUS Bus Object.
 */
ether_addr getfromInventory(sdbusplus::bus::bus& bus);

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

/** @brief Determines if the mac address is locally managed
 *  @param[in] mac - The mac address
 *  @return True if local admin bit is set
 */
bool isLocalAdmin(const ether_addr& mac);

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

/** @brief Copies data from a buffer into a copyable type
 *
 *  @param[in] data - The data buffer being extracted from
 *  @param[in] emsg - The message to print if extraction fails
 *  @return The copyable type with data populated
 */
template <typename T>
T copyFrom(std::string_view data, const char* emsg = "Extract Failed")
{
    static_assert(std::is_trivially_copyable_v<T>);
    T ret;
    if (data.size() < sizeof(ret))
    {
        throw std::runtime_error(emsg);
    }
    std::memcpy(&ret, data.data(), sizeof(ret));
    return ret;
}

/** @brief Extracts data from a buffer into a copyable type
 *         Updates the data buffer to show that data was removed
 *
 *  @param[in,out] data - The data buffer being extracted from
 *  @param[in] emsg     - The message to print if extraction fails
 *  @return The copyable type with data populated
 */
template <typename T>
T extract(std::string_view& data, const char* emsg = "Extract Failed")
{
    T ret = copyFrom<T>(data, emsg);
    data.remove_prefix(sizeof(ret));
    return ret;
}

/** @brief Compares two of the same trivially copyable types
 *
 *  @param[in] a - The data buffer being extracted from
 *  @param[in] b - The message to print if extraction fails
 *  @return True if the parameters are bitwise identical
 */
template <typename T>
bool equal(const T& a, const T& b)
{
    static_assert(std::is_trivially_copyable_v<T>);
    return memcmp(&a, &b, sizeof(T)) == 0;
}

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
