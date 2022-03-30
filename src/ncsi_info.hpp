#pragma once

#include "ncsi_util.hpp"

#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/event.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Network/NCSI/server.hpp>

#define indexInt 2
#define packageInt 0

namespace phosphor
{
namespace eeprom
{

using ConfigIntf = sdbusplus::xyz::openbmc_project::Network::server::NCSI;
using ncsiIface = sdbusplus::server::object::object<ConfigIntf>;

class ncsi : public ncsiIface
{
  public:
    ncsi() = default;
    ncsi(const ncsi&) = delete;
    ncsi& operator=(const ncsi&) = delete;
    ncsi(ncsi&&) = delete;
    ncsi& operator=(ncsi&&) = delete;
    virtual ~ncsi() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     */
    ncsi(sdbusplus::bus::bus& bus, const char* objPath);

    /** @ To get the NCSI information from this member function.
     */
    size_t get_ncsi_info();

  protected:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Path of Object. */
    std::string objectPath;
};
/* Need a custom deleter for freeing up sd_event */
struct EventDeleter
{
    void operator()(sd_event* event) const
    {
        sd_event_unref(event);
    }
};
using EventPtr = std::unique_ptr<sd_event, EventDeleter>;

} // namespace eeprom
} // namespace phosphor
