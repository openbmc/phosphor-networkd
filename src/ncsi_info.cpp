#include "config.h"

#include "ncsi_info.hpp"

#include "ethernet_interface.hpp"
#include "netlink.hpp"
#include "util.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <stdplus/raw.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

ncsiPackIntf::ncsiPackIntf(sdbusplus::bus_t& bus, const char* objPath,
                           EthernetInterface& parent) :
    ncsiPackageIntf(bus, objPath, ncsiPackageIntf::action::defer_emit),
    parent(parent)
{
    this->selected(true);
    this->hwArbiteration(true);
    this->ready(true);

    emit_object_added();
}

ncsiChlIntf::ncsiChlIntf(sdbusplus::bus_t& bus, const char* objPath,
                         EthernetInterface& parent) :
    ncsiChannelIntf(bus, objPath, ncsiChannelIntf::action::defer_emit),
    parent(parent)
{
    this->ready(true);
    this->enabled(true);

    emit_object_added();
}
} // namespace network
} // namespace phosphor
