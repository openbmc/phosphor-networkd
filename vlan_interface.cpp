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
                             uint16_t vlanID,
                             EthernetInterface& intf,
                             Manager& parent ) :
        DeleteIface(bus, objPath.c_str(), true),
        EthernetInterface(bus, objPath, dhcpEnabled,
                          parent),
        vlanID(vlanID),
        parentInterface(intf)
{
    confDir = parentInterface.confDir;
    // Emit deferred signal.
    DeleteIface::emit_object_added();
}

void VlanInterface::writeDeviceFile()
{
    using namespace std::string_literals;
    fs::path confPath = confDir;
    std::string fileName = interfaceName() + ".netdev"s;
    confPath /= fileName;
    std::fstream stream;
    stream.open(confPath.c_str(), std::fstream::out);
    if (!stream.is_open())
    {
        log<level::ERR>("Unable to write the VLAN device file",
                        entry("FILE=%s",confPath.c_str()));
        elog<InternalFailure>();
    }
    stream << "[" << "NetDev" << "]\n";
    stream << "Name=" << interfaceName() << "\n";
    stream << "Kind=vlan" << "\n";
    stream << "[VLAN]" << "\n";
    stream << "Id=" << vlanID << "\n";
    stream.close();
}

void VlanInterface::delete_()
{
    parentInterface.deleteVLANObject(interfaceName());
}

}//namespace network
}//namespace phosphor
