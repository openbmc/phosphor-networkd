#pragma once

#include <unistd.h>

#include "config.h"
#include "types.hpp"
#include <sdbusplus/bus.hpp>
#include <systemd/sd-event.h>

namespace phosphor
{
namespace network
{

/* Need a custom deleter for freeing up sd_event */
struct EventDeleter
{
    void operator()(sd_event* event) const
    {
        event = sd_event_unref(event);
    }
};

using EventPtr = std::unique_ptr<sd_event, EventDeleter>;


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

/** @brief Delete the given interface.
 *  @param[in] intf - interface name.
 */
void deleteInterface(const std::string& intf);


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
