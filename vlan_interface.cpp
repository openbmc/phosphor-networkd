#include "config.h"
#include "ipaddress.hpp"
#include "ethernet_interface.hpp"
#include "vlan_interface.hpp"
#include "network_manager.hpp"
#include "routing_table.hpp"

#include <phosphor-logging/log.hpp>

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;

VlanInterface::VlanInterface(sdbusplus::bus::bus& bus,
                             const std::string& objPath,
                             bool dhcpEnabled,
                             const uint8_t vlanID,
                             Manager& parent ) :
                                DeleteIface(bus, objPath.c_str(), true),
                                EthernetInterface(bus, objPath, dhcpEnabled,
                                                  parent),
                                vlanID(vlanID)
{
    auto intfName = objPath.substr(objPath.rfind("/") + 1);;
    interfaceName(intfName);
    createIPAddressObjects();
    writeDeviceFile();
    // Emit deferred signal.
    DeleteIface::emit_object_added();
}

void VlanInterface::writeDeviceFile()
{
    using namespace std::string_literals;
    fs::path confPath = NETWORK_CONF_DIR;
    std::string fileName = interfaceName() + std::to_string(vlanID) + ".dev"s;
    confPath /= fileName;
    std::fstream stream;
    stream.open(confPath.c_str(), std::fstream::out);

    stream << "[" << "NetDev" << "]\n";
    stream << "Name=" << interfaceName() << "\n";
    stream << "Kind=vlan" << "\n";
    stream << "[VLAN]" << "\n";
    stream << "Id=" << vlanID << "\n";
    stream.close();
}

void VlanInterface::delete_()
{
    //parent.deleteObject(interfaceName());
}

}//namespace network
}//namespace phosphor
