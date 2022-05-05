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

    void setBIOSTableAttrs()
    {
        biosTableAttrs.clear();
        setIf0DefaultBIOSTableAttrs();
        setIf1DefaultBIOSTableAttrs();
        setDefaultHostnameInBIOSTableAttrs();
    }

    friend class TestHypNetworkManager;
};

} // namespace network
} // namespace phosphor
