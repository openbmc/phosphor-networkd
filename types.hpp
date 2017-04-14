#include <list>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{

using IntfName = std::string;

struct AddrInfo {
    uint8_t addrType;
    std::string ipaddress;
    uint16_t prefix;
}

using AddrList = std::list<AddrInfo>;
using IntfAddrMap = std::map<IntfName, AddrList>;


}//namespace network
}//namespace phosphor
