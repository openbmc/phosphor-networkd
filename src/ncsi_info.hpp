#pragma once

#include "types.hpp"

#include <linux/netlink.h>

#include <cstdint>
#include <optional>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <xyz/openbmc_project/Network/NCSIChannel/server.hpp>
#include <xyz/openbmc_project/Network/NCSIPackage/server.hpp>

namespace phosphor
{
namespace network
{
using ncsiPackageIntf = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::NCSIPackage>;
using ncsiChannelIntf = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Network::server::NCSIChannel>;

class EthernetInterface;

class ncsiPackIntf : public ncsiPackageIntf
{
  public:
    ncsiPackIntf() = default;
    ncsiPackIntf(const ncsiPackIntf&) = delete;
    ncsiPackIntf& operator=(const ncsiPackIntf&) = delete;
    ncsiPackIntf(ncsiPackIntf&&) = delete;
    ncsiPackIntf& operator=(ncsiPackIntf&&) = delete;
    virtual ~ncsiPackIntf() = default;
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     */

    ncsiPackIntf(sdbusplus::bus_t& bus, const char* objPath,
                 EthernetInterface& parent);

  private:
    EthernetInterface& parent;
};

class ncsiChlIntf : public ncsiChannelIntf
{
  public:
    ncsiChlIntf() = default;
    ncsiChlIntf(const ncsiChlIntf&) = delete;
    ncsiChlIntf& operator=(const ncsiChlIntf&) = delete;
    ncsiChlIntf(ncsiChlIntf&&) = delete;
    ncsiChlIntf& operator=(ncsiChlIntf&&) = delete;
    virtual ~ncsiChlIntf() = default;
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     */

    ncsiChlIntf(sdbusplus::bus_t& bus, const char* objPath,
                EthernetInterface& parent);

  private:
    EthernetInterface& parent;
};

} // namespace network
} // namespace phosphor
