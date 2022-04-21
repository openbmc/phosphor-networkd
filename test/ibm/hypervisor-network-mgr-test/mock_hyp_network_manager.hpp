#pragma once

#include "config.h"

#include "hyp_network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

class MockHypManager : public phosphor::network::HypNetworkMgr
{
  public:
    MockHypManager(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                   const char* path) :
        phosphor::network::HypNetworkMgr(bus, event, path)
    {
    }

    void createIfObjects()
    {
        setBIOSTableAttrs();
        interfaces.emplace(
            "eth0", std::make_shared<phosphor::network::HypEthInterface>(
                        bus, (objectPath + "/eth0").c_str(), "eth0", *this));
        interfaces.emplace(
            "eth1", std::make_shared<phosphor::network::HypEthInterface>(
                        bus, (objectPath + "/eth1").c_str(), "eth1", *this));
    }
    friend class TestHypNetworkManager;
};

} // namespace network
} // namespace phosphor
