#pragma once

#include <unistd.h>

#include "config.h"
#include "types.hpp"
#include <sdbusplus/bus.hpp>
#include <regex>

namespace phosphor
{
namespace network
{

constexpr auto macRegex = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$";
constexpr auto macLocalAdminMask = 0x20;

/* @brief converts the given subnet into prefix notation.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] mask - Subnet Mask.
 * @returns prefix.
 */
uint8_t toCidr(int addressFamily, const std::string& mask);

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
bool isLinkLocal(const std::string& address);

/* @brief gets the network section of the ip adress.
 * @param[in] addressFamily - IP address family(AF_INET/AF_INET6).
 * @param[in] ipaddress - IP address.
 * @param[in] prefix - prefix length.
 * @returns network section of the ipaddress.
 */
std::string getNetworkID(int addressFamily, const std::string& ipaddress,
                         uint8_t prefix);

/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
IntfAddrMap getInterfaceAddrs();

/** @brief Restart the systemd unit
 *  @param[in] unit - systemd unit name which needs to be
 *                    restarted.
 */
inline void restartSystemdUnit(const std::string& unit)
{
    auto bus = sdbusplus::bus::new_default();
    auto method = bus.new_method_call(
                      SYSTEMD_BUSNAME,
                      SYSTEMD_PATH,
                      SYSTEMD_INTERFACE,
                      "RestartUnit");

    method.append(unit, "replace");
    bus.call_noreply(method);

}

inline bool validateMac(const std::string value)
{
    bool matched = false;
    std::regex regexToCheck(macRegex);
    matched = std::regex_search(value, regexToCheck);
    return matched;
}

inline uint64_t getIntMacAddress(const std::string& value)
{
    unsigned char mac[6];

    sscanf(value.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           mac + 0, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5);
    return
        uint64_t(mac[0]) << 40 |
        uint64_t(mac[1]) << 32 |
        uint64_t(mac[2]) << 24 |
        uint64_t(mac[3]) << 16 |
        uint64_t(mac[4]) << 8 |
        uint64_t(mac[5]);
}

} //namespace network

class Descriptor
{
    private:
        /** default value */
        int fd = -1;

    public:
        Descriptor() = delete;
        Descriptor(const Descriptor&) = delete;
        Descriptor& operator=(const Descriptor&) = delete;
        Descriptor(Descriptor&&) = delete;
        Descriptor& operator=(Descriptor &&) = delete;

        Descriptor(int fd) : fd(fd) {}

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

} //namespace phosphor
