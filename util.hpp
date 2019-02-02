#pragma once

#include "config.h"

#include "types.hpp"

#include <unistd.h>

#include <regex>
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
constexpr auto ZEROMACADDRESS = "00:00:00:00:00:00";

namespace mac_address
{

constexpr auto regex = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$";
constexpr auto localAdminMask = 0x020000000000;
constexpr auto broadcastMac = 0xFFFFFFFFFFFF;

constexpr auto format = "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx";
constexpr size_t size = 18;

/** @brief validate the mac address
 *  @param[in] value - MAC address.
 *  @returns true if validate otherwise false.
 */
inline bool validate(const std::string& value)
{
    std::regex regexToCheck(regex);
    return std::regex_search(value, regexToCheck) &&
           value.find(ZEROMACADDRESS) != 0;
}

/** @brief gets the MAC address from the Inventory.
 *  @param[in] bus - DBUS Bus Object.
 */
std::string getfromInventory(sdbusplus::bus::bus& bus);

/** @brief Converts the given mac address bytes into a string
 *  @param[in] bytes - The mac address
 *  @returns A valid mac address string
 */
std::string toString(const MacAddr& mac);

namespace internal
{
/** @brief Converts the given mac address into unsigned 64 bit integer
 *  @param[in] value - MAC address.
 *  @returns converted unsigned 64 bit number.
 */
inline uint64_t convertToInt(const std::string& value)
{
    unsigned char mac[6];

    sscanf(value.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac + 0, mac + 1,
           mac + 2, mac + 3, mac + 4, mac + 5);
    return static_cast<uint64_t>(mac[0]) << 40 |
           static_cast<uint64_t>(mac[1]) << 32 |
           static_cast<uint64_t>(mac[2]) << 24 |
           static_cast<uint64_t>(mac[3]) << 16 |
           static_cast<uint64_t>(mac[4]) << 8 | static_cast<uint64_t>(mac[5]);
}

/** @brief Converts the lower nibble of a byte value to a hex digit
 */
inline char toHex(std::byte byte)
{
    uint8_t val = std::to_integer<uint8_t>(byte) & 0xf;
    return val < 10 ? '0' + val : 'A' + (val - 10);
}
} // namespace internal
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

/* @brief gets the network section of the ip address.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] ipaddress - IP address.
 * @param[in] prefix - prefix length.
 * @returns network section of the ipaddress.
 */
std::string getNetworkID(int addressFamily, const std::string& ipaddress,
                         uint8_t prefix);

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
    using expandType = char* [];

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
