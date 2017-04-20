#include "ipaddress.hpp"
#include "ethernet_interface.hpp"

#include <phosphor-logging/log.hpp>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;

IPAddress::IPAddress(sdbusplus::bus::bus& bus,
          const char* objPath,
          EthernetInterface& parent,
          IPProtocol::Protocol type,
          const std::string& ipaddress,
          uint8_t prefixLength,
          const std::string& gateway):
          IPIfaces(bus,objPath,true),
          parent(parent)
{
   this->address(ipaddress);
   this->prefixLength(prefixLength);
   this->gateway(gateway);
   this->type(type);
   // Emit deferred signal.
   this->emit_object_added();
}


void IPAddress::delete_()
{
    parent.deleteObject(this->address());
}

}//namespace network
}//namespace phosphor
