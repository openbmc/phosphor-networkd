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
        EthernetInterface(std::forward<Args>(args)..., /*nicEnabled=*/true)
    {}

    MOCK_METHOD((ServerList), getNTPServerFromTimeSyncd, (), (override));
    MOCK_METHOD((ServerList), getNameServerFromResolvd, (), (const override));
};
} // namespace network
} // namespace phosphor
