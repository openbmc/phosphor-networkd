#include "config.h"

#include "network_config.hpp"

#include "config_parser.hpp"

namespace phosphor
{
namespace network
{

namespace bmc
{
void writeDHCPDefault(const std::filesystem::path& filename,
                      std::string_view interface)
{
    config::Parser config;
    config.map["Match"].emplace_back()["Name"].emplace_back(interface);
    {
        auto& network = config.map["Network"].emplace_back();
        network["DHCP"].emplace_back("true");
        auto& lla = network["LinkLocalAddressing"];
#ifdef LINK_LOCAL_AUTOCONFIGURATION
        lla.emplace_back("true");
#else
        lla.emplace_back("false");
#endif
        auto& ra = network["IPv6AcceptRA"];
#ifdef ENABLE_IPV6_ACCEPT_RA
        ra.emplace_back("true");
#else
        ra.emplace_back("false");
#endif
    }
    {
        auto& dhcp = config.map["DHCP"].emplace_back();
        dhcp["ClientIdentifier"].emplace_back("mac");
        dhcp["UseDNS"].emplace_back("true");
        dhcp["UseDomains"].emplace_back("true");
        dhcp["UseNTP"].emplace_back("true");
        dhcp["UseHostname"].emplace_back("true");
        dhcp["SendHostname"].emplace_back("true");
    }
    config.map["IPv6AcceptRA"].emplace_back()["DHCPv6Client"].emplace_back(
        "true");
    config.writeFile(filename);
}
} // namespace bmc

} // namespace network
} // namespace phosphor
