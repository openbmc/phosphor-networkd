#pragma once
#include "config_parser.hpp"
#include "mock_ethernet_interface.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

void initializeTimers();
void refreshObjects();

class MockManager : public Manager
{
  public:
    MockManager(sdbusplus::bus_t& bus, const char* path,
                const std::string& dir) :
        Manager(bus, path, dir)
    {
    }

    void createInterfaces() override
    {
        interfaces.clear();
        for (auto& interface : system::getInterfaces())
        {
            config::Parser config(
                config::pathForIntfConf(confDir, *interface.name));
            auto intf = std::make_unique<MockEthernetInterface>(
                bus, *this, interface, objectPath, config);
            intf->createIPAddressObjects();
            intf->createStaticNeighborObjects();
            intf->loadNameServers(config);
            this->interfaces.emplace(
                std::make_pair(std::move(*interface.name), std::move(intf)));
        }
    }

    MOCK_METHOD(void, reloadConfigs, (), (override));
};

} // namespace network
} // namespace phosphor
