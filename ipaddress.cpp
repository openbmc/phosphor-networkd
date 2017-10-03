#include "ipaddress.hpp"
#include "ethernet_interface.hpp"
#include "util.hpp"

#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

IPAddress::IPAddress(sdbusplus::bus::bus& bus,
          const char* objPath,
          EthernetInterface& parent,
          IP::Protocol type,
          const std::string& ipaddress,
          IP::AddressOrigin origin,
          uint8_t prefixLength,
          const std::string& gateway):
          IPIfaces(bus, objPath, true),
          parent(parent)
{
   this->address(ipaddress);
   this->prefixLength(prefixLength);
   this->gateway(gateway);
   this->type(type);
   this->origin(origin);

   // Emit deferred signal.
   emit_object_added();
}


void IPAddress::delete_()
{
    if (parent.dHCPEnabled())
    {
        log<level::ERR>("DHCP enabled on the interface"),
                        entry("INTERFACE=%s",parent.interfaceName().c_str());
        elog<InternalFailure>();
    }

    if (isLinkLocalIP(address(), (type() == IP::Protocol::IPv4 ? "ipv4" : "ipv6")))  //linklocakIp
    {
        log<level::ERR>("This interface is for LinkLocal"),
                        entry("INTERFACE=%s",parent.interfaceName().c_str());
        elog<InternalFailure>();
    }

    parent.deleteObject(address());
}

}//namespace network
}//namespace phosphor
