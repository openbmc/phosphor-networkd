#pragma once

#include "hyp_ethernet_interface.hpp"
#include "hyp_ip_interface.hpp"

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
    {}

    void createIPAddrObj()
    {
        addrs.emplace(
            "eth0",
            std::make_unique<HypIPAddress>(
                bus, "/xyz/openbmc_test/network/hypervisor/eth0/ipv4/addr0",
                *this, HypIP::Protocol::IPv4, "9.9.9.9",
                HypIP::AddressOrigin::Static, 0, "9.9.9.1", "if0"));
        addrs.emplace(
            "eth1",
            std::make_unique<HypIPAddress>(
                bus, "/xyz/openbmc_test/network/hypervisor/eth1/ipv4/addr0",
                *this, HypIP::Protocol::IPv4, "8.8.8.8",
                HypIP::AddressOrigin::Static, 0, "8.8.8.1", "if1"));
    }

    friend class TestHypEthernetInterface;
};
} // namespace network
} // namespace phosphor
