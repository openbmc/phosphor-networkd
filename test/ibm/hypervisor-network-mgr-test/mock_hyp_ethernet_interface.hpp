#pragma once

#include "hyp_ethernet_interface.hpp"

namespace phosphor
{
namespace network
{
class MockHypEthernetInterface : public HypEthInterface
{
  public:
    MockHypEthernetInterface(sdbusplus::bus::bus& bus, const char* path,
                             const std::string& intfName,
                             HypNetworkMgr& parent) :
        HypEthInterface(bus, path, intfName, parent)
    {
    }
    friend class TestHypEthernetInterface;
};
} // namespace network
} // namespace phosphor
