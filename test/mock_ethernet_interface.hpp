#pragma once

#include "ethernet_interface.hpp"
#include "mock_syscall.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{
class MockEthernetInterface : public EthernetInterface
{
  public:
    MockEthernetInterface(sdbusplus::bus_t& bus, const std::string& objPath,
                          const config::Parser& config, Manager& parent,
                          bool emitSignal) :
        EthernetInterface(bus, objPath, config, parent, emitSignal,
                          /*nicEnabled=*/true)
    {
    }

    MOCK_METHOD((ServerList), getNameServerFromResolvd, (), (override));
    friend class TestEthernetInterface;
};
} // namespace network
} // namespace phosphor
