#include "config.h"
#include "ethernet_interface.hpp"
#include "vlan_interface.hpp"
#include "network_manager.hpp"

#include <phosphor-logging/log.hpp>
#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/elog-errors.hpp>

#include <string>
#include <algorithm>
#include <fstream>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

VlanInterface::VlanInterface(sdbusplus::bus::bus& bus,
                             const std::string& objPath,
                             bool dhcpEnabled,
                             uint32_t vlanID,
                             EthernetInterface& intf,
                             Manager& parent ) :
        Interfaces(bus, objPath.c_str(), true),
        EthernetInterface(bus, objPath, dhcpEnabled,
                          parent),
        parentInterface(intf)
{
    id(vlanID);
    auto intfName = objPath.substr(objPath.rfind("/") + 1);
    VlanIface::interfaceName(intfName);

    dHCPEnabled(parentInterface.dHCPEnabled());
    mACAddress(parentInterface.mACAddress());

    confDir = parentInterface.confDir;
    Interfaces::emit_object_added();
}

void VlanInterface::writeDeviceFile()
{
    using namespace std::string_literals;
    fs::path confPath = NETWORK_CONF_DIR;

    if (!fs::create_directories(confPath))
    {
        log<level::ERR>("Unable to create the network conf dir",
                         entry("DIR=%s", confPath.c_str()));
        elog<InternalFailure>();
    }

    std::string fileName = EthernetInterface::interfaceName() + ".netdev"s;
    confPath /= fileName;
    std::fstream stream;
    try
    {
        stream.open(confPath.c_str(), std::fstream::out);
    }
    catch (std::ios_base::failure& e)
    {
        log<level::ERR>("Unable to open the VLAN device file",
                         entry("FILE=%s", confPath.c_str()),
                         entry("ERROR=%s", e.what()));
        elog<InternalFailure>();

    }

    stream << "[" << "NetDev" << "]\n";
    stream << "Name=" << EthernetInterface::interfaceName() << "\n";
    stream << "Kind=vlan" << "\n";
    stream << "[VLAN]" << "\n";
    stream << "Id=" << id() << "\n";
    stream.close();
}

void VlanInterface::delete_()
{
    parentInterface.deleteVLANObject(EthernetInterface::interfaceName());
}

}//namespace network
}//namespace phosphor
