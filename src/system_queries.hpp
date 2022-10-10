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
    std::optional<std::string> name;
    std::optional<ether_addr> mac;
    std::optional<unsigned> mtu;

    inline constexpr bool operator==(const InterfaceInfo& rhs) const noexcept
    {
        return idx == rhs.idx && flags == rhs.flags && name == rhs.name &&
               mac == rhs.mac && mtu == rhs.mtu;
    }
};

namespace detail
{
InterfaceInfo parseInterface(const nlmsghdr& hdr, std::string_view msg);
bool validateNewInterface(const InterfaceInfo& info);
} // namespace detail

/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
std::vector<InterfaceInfo> getInterfaces();

} // namespace phosphor::network::system
