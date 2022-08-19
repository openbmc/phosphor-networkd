#include "vlan_interface.hpp"

#include "config_parser.hpp"
#include "ethernet_interface.hpp"
#include "network_manager.hpp"

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
                             const config::Parser& config, bool nicEnabled,
                             uint32_t vlanID, EthernetInterface& intf,
                             Manager& parent) :
    VlanIface(bus, objPath.c_str()),
    DeleteIface(bus, objPath.c_str()),
    EthernetInterface(bus, objPath, config, parent, true, nicEnabled),
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
    config::Parser config;
    auto& netdev = config.map["NetDev"].emplace_back();
    netdev["Name"].emplace_back(EthernetInterface::interfaceName());
    netdev["Kind"].emplace_back("vlan");
    config.map["VLAN"].emplace_back()["Id"].emplace_back(std::to_string(id()));
    config.writeFile(config::pathForIntfDev(
        manager.getConfDir(), EthernetInterface::interfaceName()));
}

void VlanInterface::delete_()
{
    parentInterface.deleteVLANObject(EthernetInterface::interfaceName());
}

} // namespace network
} // namespace phosphor
