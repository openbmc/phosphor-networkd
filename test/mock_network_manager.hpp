#include "config.h"

#include "mock_ethernet_interface.hpp"
#include "network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

class MockManager : public phosphor::network::Manager
{
  public:
    MockManager(sdbusplus::bus::bus& bus, const char* path,
                const std::string& dir) :
        phosphor::network::Manager(bus, path, dir)
    {
        createInterfaces();
    }

    void createInterfaces()
    {
        // clear all the interfaces first
        interfaces.clear();
        auto interfaceStrList = getInterfaces();
        for (auto& interface : interfaceStrList)
        {
            fs::path objPath = objectPath;
            auto index = interface.find(".");
            // interface can be of vlan type or normal ethernet interface.
            // vlan interface looks like "interface.vlanid",so here by looking
            // at the interface name we decide that we need
            // to create the vlaninterface or normal physical interface.
            if (index != std::string::npos)
            {
                // it is vlan interface
                auto interfaceName = interface.substr(0, index);
                auto vlanid = interface.substr(index + 1);
                uint32_t vlanInt = std::stoul(vlanid);
                interfaces[interfaceName]->loadVLAN(vlanInt);
                continue;
            }
            // normal ethernet interface
            objPath /= interface;
            auto dhcp = getDHCPValue(confDir, interface);
            auto intf =
                std::make_shared<phosphor::network::MockEthernetInterface>(
                    bus, objPath.string(), dhcp, *this, true);
            intf->createIPAddressObjects();
            intf->createStaticNeighborObjects();
            this->interfaces.emplace(
                std::make_pair(std::move(interface), std::move(intf)));
        }
    }
    MOCK_METHOD1(restartSystemdUnit, void(const std::string& service));
};

} // namespace network
} // namespace phosphor
