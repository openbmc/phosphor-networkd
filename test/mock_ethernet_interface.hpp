#pragma once
#include "ethernet_interface.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{
class MockEthernetInterface : public EthernetInterface
{
  public:
    template <typename... Args>
    MockEthernetInterface(Args&&... args) :
        EthernetInterface(std::forward<Args>(args)..., /*emitSignal=*/false,
                          /*nicEnabled=*/true)
    {
    }

    MOCK_METHOD((ServerList), getNameServerFromResolvd, (), (override));
    friend class TestEthernetInterface;
};
} // namespace network
} // namespace phosphor
