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
    MockEthernetInterface(sdbusplus::bus::bus& bus, const std::string& objPath,
                          DHCPConf dhcpEnabled, Manager& parent,
                          bool emitSignal) :
        EthernetInterface(bus, objPath, dhcpEnabled, parent, emitSignal,
                          /*nicEnabled=*/true)
    {
    }

    MOCK_METHOD((ServerList), getNameServerFromResolvd, (), (override));
    MOCK_METHOD((), loadNTPServers, (), (override));
    friend class TestEthernetInterface;
};
} // namespace network
} // namespace phosphor
