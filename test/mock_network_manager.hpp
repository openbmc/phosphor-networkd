#pragma once
#include "config_parser.hpp"
#include "mock_ethernet_interface.hpp"
#include "network_manager.hpp"
#include "util.hpp"

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
        // clear all the interfaces first
        interfaces.clear();
        auto interfaceStrList = getSystemInterfaces();
        for (auto& interface : interfaceStrList)
        {
            fs::path objPath = objectPath;
            // normal ethernet interface
            objPath /= interface;
            config::Parser config(config::pathForIntfConf(confDir, interface));
            auto intf = std::make_unique<MockEthernetInterface>(
                bus, objPath.string(), config, *this);
            intf->createIPAddressObjects();
            intf->createStaticNeighborObjects();
            intf->loadNameServers(config);
            this->interfaces.emplace(
                std::make_pair(std::move(interface), std::move(intf)));
        }
    }

    MOCK_METHOD(void, reloadConfigs, (), (override));
};

} // namespace network
} // namespace phosphor
