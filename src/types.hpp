#pragma once
#include "config.h"

#include <function2/function2.hpp>
#include <stdplus/net/addr/ether.hpp>
#include <stdplus/net/addr/ip.hpp>
#include <stdplus/net/addr/subnet.hpp>

#include <array>
#include <optional>
#include <string>
#include <unordered_map>

namespace phosphor::network
{

class DelayedExecutor
{
  public:
    virtual ~DelayedExecutor() = default;

    virtual void schedule() = 0;
    virtual void setCallback(fu2::unique_function<void()>&& cb) = 0;
};

#if ENABLE_BOND_SUPPORT
/** @struct BondInfo
 *  @brief Information about bond interface
 */
struct BondInfo
{
    std::string activeSlave{};
    uint8_t mode;
    uint8_t miiMonitor;

    constexpr bool operator==(const BondInfo& rhs) const noexcept
    {
        return activeSlave == rhs.activeSlave && mode == rhs.mode &&
               miiMonitor == rhs.miiMonitor;
    }
};
#endif

/** @class InterfaceInfo
 *  @brief Information about interfaces from the kernel
 */
struct InterfaceInfo
{
    unsigned short type;
    unsigned idx;
    unsigned flags;
    std::optional<std::string> name = std::nullopt;
    std::optional<stdplus::EtherAddr> mac = std::nullopt;
    std::optional<unsigned> mtu = std::nullopt;
    std::optional<unsigned> parent_idx = std::nullopt;
    std::optional<std::string> kind = std::nullopt;
    std::optional<uint16_t> vlan_id = std::nullopt;
#if ENABLE_BOND_SUPPORT
    std::optional<BondInfo> bondInfo = std::nullopt;
#endif

    constexpr bool operator==(const InterfaceInfo& rhs) const noexcept
    {
#if ENABLE_BOND_SUPPORT
        return idx == rhs.idx && flags == rhs.flags && name == rhs.name &&
               mac == rhs.mac && mtu == rhs.mtu &&
               parent_idx == rhs.parent_idx && kind == rhs.kind &&
               vlan_id == rhs.vlan_id && bondInfo == rhs.bondInfo;
#else
        return idx == rhs.idx && flags == rhs.flags && name == rhs.name &&
               mac == rhs.mac && mtu == rhs.mtu &&
               parent_idx == rhs.parent_idx && kind == rhs.kind &&
               vlan_id == rhs.vlan_id;
#endif
    }
};

/** @class AddressInfo
 *  @brief Information about a addresses from the kernel
 */
struct AddressInfo
{
    unsigned ifidx;
    stdplus::SubnetAny ifaddr;
    uint8_t scope;
    uint32_t flags;

    constexpr bool operator==(const AddressInfo& rhs) const noexcept
    {
        return ifidx == rhs.ifidx && ifaddr == rhs.ifaddr &&
               scope == rhs.scope && flags == rhs.flags;
    }
};

/** @class NeighborInfo
 *  @brief Information about a neighbor from the kernel
 */
struct NeighborInfo
{
    unsigned ifidx;
    uint16_t state;
    std::optional<stdplus::InAnyAddr> addr;
    std::optional<stdplus::EtherAddr> mac;

    constexpr bool operator==(const NeighborInfo& rhs) const noexcept
    {
        return ifidx == rhs.ifidx && state == rhs.state && addr == rhs.addr &&
               mac == rhs.mac;
    }
};

/** @class StaticGatewayInfo
 *  @brief Information about a static gateway from the kernel
 */
struct StaticGatewayInfo
{
    unsigned ifidx;
    std::optional<std::string> gateway;
    std::optional<std::string> protocol;

    constexpr bool operator==(const StaticGatewayInfo& rhs) const noexcept
    {
        return ifidx == rhs.ifidx && gateway == rhs.gateway;
    }
};

/** @brief Contains all of the object information about the interface */
struct AllIntfInfo
{
    InterfaceInfo intf;
    std::optional<stdplus::In4Addr> defgw4 = std::nullopt;
    std::optional<stdplus::In6Addr> defgw6 = std::nullopt;
    std::unordered_map<stdplus::SubnetAny, AddressInfo> addrs = {};
    std::unordered_map<stdplus::InAnyAddr, NeighborInfo> staticNeighs = {};
    std::unordered_map<std::string, StaticGatewayInfo> staticGateways = {};
};

} // namespace phosphor::network
