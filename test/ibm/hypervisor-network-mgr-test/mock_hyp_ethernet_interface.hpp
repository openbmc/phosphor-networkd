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
        ifaddr_eth0.emplace(*addr_eth0, 0);

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

    bool createIP(MockHypEthernetInterface& interface, std::string intfLabel,
                  HypIP::Protocol protType, const std::string& ipaddress,
                  uint8_t prefixLength, const std::string& gateway)
    {
        HypIP::AddressOrigin origin = HypIP::AddressOrigin::Static;

        std::optional<stdplus::InAnyAddr> addr;
        try
        {
            switch (protType)
            {
                case HypIP::Protocol::IPv4:
                    if (interface.dhcp4())
                    {
                        interface.dhcp4(false);
                    }
                    addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
                    break;
                case HypIP::Protocol::IPv6:
                    if (interface.dhcp6())
                    {
                        interface.dhcp6(false);
                    }
                    addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
                    break;
                default:
                    throw std::logic_error("Exhausted protocols");
            }
            if (!std::visit([](auto ip) { return validIntfIP(ip); }, *addr))
            {
                throw std::invalid_argument("not unicast");
            }
        }
        catch (const std::exception& e)
        {
            // Invalid IP
            return false;
        }

        std::optional<stdplus::SubnetAny> ifaddr;
        try
        {
            if (prefixLength == 0)
            {
                throw std::invalid_argument("default route");
            }
            ifaddr.emplace(*addr, prefixLength);
        }
        catch (const std::exception& e)
        {
            // Invalid Prefix
            return false;
        }

        try
        {
            if (!gateway.empty())
            {
                if (protType == HypIP::Protocol::IPv4)
                {
                    validateGateway<stdplus::In4Addr>(gateway);
                }
                else if (protType == HypIP::Protocol::IPv6)
                {
                    validateGateway<stdplus::In4Addr>(gateway);
                }
            }
            else
            {
                throw std::invalid_argument("Empty gateway");
            }
        }
        catch (const std::exception& e)
        {
            // Invalid Gateway
            return false;
        }

        const std::string ipObjId = "addr0";
        std::string protocol;
        if (protType == HypIP::Protocol::IPv4)
        {
            protocol = "ipv4";
        }
        else if (protType == HypIP::Protocol::IPv6)
        {
            protocol = "ipv6";
        }

        const std::string intfLabel = "if0";
        std::string objPath = objectPath.str + "/" + protocol + "/" + ipObjId;

        addrs.erase(intfLabel);

        addrs[intfLabel] = std::make_unique<HypIPAddress>(
            bus, sdbusplus::message::object_path(objPath), *this, *ifaddr,
            gateway, origin, intfLabel);
        return true;
    }

    friend class TestHypEthernetInterface;
};
} // namespace network
} // namespace phosphor
