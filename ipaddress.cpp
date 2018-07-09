#include "ipaddress.hpp"

#include "config.h"
#include "ethernet_interface.hpp"
#include "util.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

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
            entry("INTERFACE=%s", parent.interfaceName().c_str());
        return;
    }

#ifdef LINK_LOCAL_AUTOCONFIGURATION
    if (isLinkLocalIP(address()))
    {
        log<level::ERR>("Can not delete the LinkLocal address"),
            entry("INTERFACE=%s ADDRESS=%s",
                  parent.interfaceName().c_str(), address().c_str());
        return;
    }
#endif

    parent.deleteObject(address());
}

}//namespace network
}//namespace phosphor
