#pragma once
#include "types.hpp"

#include <net/ethernet.h>

#include <cstdint>
#include <optional>
#include <stdplus/zstring.hpp>
#include <stdplus/zstring_view.hpp>
#include <string>
#include <string_view>
#include <vector>

struct nlmsghdr;

namespace phosphor::network::system
{
struct EthInfo
{
    bool autoneg;
    uint16_t speed;
};
EthInfo getEthInfo(stdplus::zstring_view ifname);

bool intfIsRunning(std::string_view ifname);

std::optional<unsigned> getMTU(stdplus::zstring_view ifname);

void setMTU(std::string_view ifname, unsigned mtu);

void setNICUp(std::string_view ifname, bool up);

/** @class InterfaceInfo
 *  @brief Information about interfaces from the kernel
 */
struct InterfaceInfo
{
    unsigned idx;
    unsigned flags;
    std::optional<std::string> name = std::nullopt;
    std::optional<ether_addr> mac = std::nullopt;
    std::optional<unsigned> mtu = std::nullopt;
    std::optional<unsigned> parent_idx = std::nullopt;
    std::optional<std::string> kind = std::nullopt;
    std::optional<uint16_t> vlan_id = std::nullopt;

    constexpr bool operator==(const InterfaceInfo& rhs) const noexcept
    {
        return idx == rhs.idx && flags == rhs.flags && name == rhs.name &&
               mac == rhs.mac && mtu == rhs.mtu &&
               parent_idx == rhs.parent_idx && kind == rhs.kind &&
               vlan_id == rhs.vlan_id;
    }
};

struct AddressFilter
{
    unsigned ifidx = 0;
};

namespace detail
{
InterfaceInfo parseInterface(const nlmsghdr& hdr, std::string_view msg);
bool validateNewInterface(const InterfaceInfo& info);
bool validateNewAddr(const AddressInfo& info,
                     const AddressFilter& filter) noexcept;
} // namespace detail

/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
std::vector<InterfaceInfo> getInterfaces();

/** @brief Get all the addreses from the system.
 *  @returns list of addresses
 */
std::vector<AddressInfo> getAddresses(const AddressFilter& filter);

} // namespace phosphor::network::system
