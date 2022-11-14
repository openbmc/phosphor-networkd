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

struct AddressFilter
{
    unsigned ifidx = 0;
};

struct NeighborFilter
{
    unsigned ifidx = 0;
};

namespace detail
{
InterfaceInfo parseInterface(const nlmsghdr& hdr, std::string_view msg);
bool validateNewAddr(const AddressInfo& info,
                     const AddressFilter& filter) noexcept;
bool validateNewNeigh(const NeighborInfo& info,
                      const NeighborFilter& filter) noexcept;
} // namespace detail

/** @brief Get all the interfaces from the system.
 *  @returns list of interface names.
 */
std::vector<InterfaceInfo> getInterfaces();

/** @brief Get all the addreses from the system.
 *  @returns list of addresses
 */
std::vector<AddressInfo> getAddresses(const AddressFilter& filter);

/** @brief Returns a list of system neighbor table
 */
std::vector<NeighborInfo> getNeighbors(const NeighborFilter& filter);

} // namespace phosphor::network::system
