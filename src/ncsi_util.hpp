#pragma once

#include <stdint.h>

#include <optional>
#include <span>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
namespace ncsi
{

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

struct ChannelInfo
{
    uint32_t id;
    bool active;
    bool forced;
    uint32_t version_major, version_minor;
    std::string version;
    uint32_t link_state;
    std::vector<uint16_t> vlan_ids;
};

struct PackageInfo
{
    uint32_t id;
    bool forced;
    std::vector<ChannelInfo> channels;
};

struct InterfaceInfo
{
    std::vector<PackageInfo> packages;
};

struct Interface
{
    using ncsiMessage = std::span<const unsigned char>;

    /* @brief  This function will ask underlying NCSI driver
     *         to send an OEM command (command type 0x50) with
     *         the specified payload as the OEM data.
     *         This function talks with the NCSI driver over
     *         netlink messages.
     * @param[in] package - NCSI Package.
     * @param[in] channel - Channel number with in the package.
     * @param[in] opcode  - NCSI Send Command sub-operation
     * @param[in] payload - OEM data to send.
     * @returns the NCSI response message to this command, or no value on error.
     */
    std::optional<std::vector<unsigned char>> sendOemCommand(
        int package, int channel, int opcode, ncsiMessage payload);

    /* @brief  This function will ask underlying NCSI driver
     *         to set a specific  package or package/channel
     *         combination as the preferred choice.
     *         This function talks with the NCSI driver over
     *         netlink messages.
     * @param[in] package - NCSI Package.
     * @param[in] channel - Channel number with in the package.
     * @returns 0 on success and negative value for failure.
     */
    int setChannel(int package, int channel);

    /* @brief  This function will ask underlying NCSI driver
     *         to clear any preferred setting from the interface.
     *         This function talks with the NCSI driver over
     *         netlink messages.
     * @returns 0 on success and negative value for failure.
     */
    int clearInterface();

    /* @brief  This function is used to dump all the info
     *         of the package and the channels underlying
     *         the package, or all packages if DEFAULT_VALUE
     *         is passed
     * @param[in] package - NCSI Package
     * @returns an InterfaceInfo with package data the specified pacakge,
     *          or all packages if none is specified.
     */
    std::optional<InterfaceInfo> getInfo(int package);

    /* @brief  This function assigns a mask controlling responses to AEN from a
     * package.
     * @param[in] mask - A 32-bit mask integer
     * @returns 0 on success and negative value for failure.
     */
    int setPackageMask(unsigned int mask);

    /* @brief  This function sets the AEN mask for the channels inside the
     * selected package.
     * @param[in] package - NCSI Package.
     * @param[in] mask - A 32-bit mask integer
     * @returns 0 on success and negative value for failure.
     */
    int setChannelMask(int package, unsigned int mask);

    int ifindex;
};

std::string to_string(Interface& interface);

} // namespace ncsi
} // namespace network
} // namespace phosphor
