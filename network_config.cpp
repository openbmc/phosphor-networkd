#include "network_config.hpp"
#include <fstream>

namespace phosphor
{
namespace network
{

namespace bmc
{
    void writeDHCPDefault(const std::string& filename,
            const std::string& interface)
    {
        std::ofstream filestream;

        filestream.open(filename);
        filestream << "[Match]\nName=" << interface <<
                "\n[Network]\nDHCP=true\n[DHCP]\nClientIdentifier=mac\n";
        filestream.close();
    }
}

}//namespace network
}//namespace phosphor
