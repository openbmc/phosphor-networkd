#include "network_config.hpp"
#include "ethernet_interface.hpp"
#include <fstream>
#include <string>

namespace phosphor {
namespace network {

namespace bmc {
void writeDHCPDefault(const std::string &filename, const std::string &interface)
{

    std::ofstream filestream;

    filestream.open(filename);
    filestream
        << "[Match]\nName="
        << interface << "\n[Network]\nDHCP=true\nLinkLocalAddressing=yes\n"
                        "IPv6AcceptRA=false\n"
                        "[DHCP]\nClientIdentifier=mac\n"
                        "[Link]\nMACAddress="
        << EthernetInterface::getMACAddress(interface) << "\n";
    filestream.close();
}
}

} // namespace network
} // namespace phosphor
