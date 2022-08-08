#include "config.h"

#include "vlan_interface.hpp"

#include "ethernet_interface.hpp"
#include "network_manager.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <string>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

VlanInterface::VlanInterface(sdbusplus::bus_t& bus, const std::string& objPath,
                             const config::Parser& config, DHCPConf dhcpEnabled,
                             bool nicEnabled, uint32_t vlanID,
                             EthernetInterface& intf, Manager& parent) :
    VlanIface(bus, objPath.c_str()),
    DeleteIface(bus, objPath.c_str()),
    EthernetInterface(bus, objPath, config, dhcpEnabled, parent, true,
                      nicEnabled),
    parentInterface(intf)
{
    id(vlanID);
    VlanIface::interfaceName(EthernetInterface::interfaceName());
    MacAddressIntf::macAddress(parentInterface.macAddress());

    emit_object_added();
}

std::string VlanInterface::macAddress(std::string)
{
    log<level::ERR>("Tried to set MAC address on VLAN");
    elog<InternalFailure>();
}

void VlanInterface::writeDeviceFile()
{
    auto confPath = config::pathForIntfDev(manager.getConfDir(),
                                           EthernetInterface::interfaceName());
    std::fstream stream(confPath.c_str(), std::fstream::out);

    stream << "[NetDev]\n";
    stream << "Name=" << EthernetInterface::interfaceName() << "\n";
    stream << "Kind=vlan\n";
    stream << "[VLAN]\n";
    stream << "Id=" << id() << "\n";

    stream.close();

    if (!stream.good())
    {
        log<level::ERR>("Unable to write the VLAN device file",
                        entry("FILE=%s", confPath.c_str()));
        elog<InternalFailure>();
    }
}

void VlanInterface::delete_()
{
    parentInterface.deleteVLANObject(EthernetInterface::interfaceName());
}

} // namespace network
} // namespace phosphor
