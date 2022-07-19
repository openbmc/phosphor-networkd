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
    MockHypEthernetInterface(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                             sdbusplus::message::object_path path,
                             std::string_view intfName,
                             stdplus::PinnedRef<HypNetworkMgr> parent) :
        HypEthInterface(bus, path, intfName, parent)
    {}

    void createIPAddrObj()
    {
        std::optional<stdplus::InAnyAddr> addr_eth0, addr_eth1;
        addr_eth0.emplace(stdplus::fromStr<stdplus::In4Addr>("9.9.9.9"));

        std::optional<stdplus::SubnetAny> ifaddr_eth0, ifaddr_eth1;
        ;
        ifaddr_eth0.emplace(*addr, 0);

        addrs.emplace(
            "eth0",
            std::make_unique<HypIPAddress>(
                bus,
                sdbusplus::message::object_path(
                    "/xyz/openbmc_test/network/hypervisor/eth0/ipv4/addr0"),
                *this, *ifaddr_eth0, "9.9.9.1", HypIP::AddressOrigin::Static,
                "if0"));

        addr_eth1.emplace(stdplus::fromStr<stdplus::In4Addr>("8.8.8.8"));
        ifaddr_eth1.emplace(*addr_eth1, 0);

        addrs.emplace(
            "eth1",
            std::make_unique<HypIPAddress>(
                bus,
                sdbusplus::message::object_path(
                    "/xyz/openbmc_test/network/hypervisor/eth1/ipv4/addr0"),
                *this, *ifaddr_eth1, "8.8.8.1", HypIP::AddressOrigin::Static,
                "if1"));
    }

    friend class TestHypEthernetInterface;
};
} // namespace network
} // namespace phosphor
