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

    std::map<std::string, std::variant<int64_t, std::string>> biosTableAttrs;

    void setDefaultBIOSTableAttrs()
    {
        biosTableAttrs.clear();
        biosTableAttrs.emplace("vmi_hostname", "defaultHostname");
    }
    friend class TestHypNetworkManager;
};
} // namespace network
} // namespace phosphor
