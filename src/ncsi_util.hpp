#pragma once

#include <span>

namespace phosphor
{
namespace network
{
namespace ncsi
{

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

// AEN Interrupts
constexpr auto disableAENMask = 0x00000000;
constexpr auto enableLinkAENMask = 0x00000001;
constexpr auto enableLinkConfigAENMask = 0x00000010;
constexpr auto enableLinkNCdriverAENMask = 0x00000011;
constexpr auto enableConfigAENMask = 0x00000100;
constexpr auto enableConfigNCdriverAENMask = 0x00000101;
constexpr auto enableHostNCdriverAENMask = 0x00000110;
constexpr auto enableAENMask = 0x00000111;

// AEN Response and Reason Codes
constexpr auto AEN_RESPONSE_CODE = 18;
constexpr auto AEN_REASON_CODE = 20;

// NCSI PACKET TYPE
// Control packet type for Asynchronous Event Notification
constexpr auto NCSI_CMD_AEN_ENABLE = 0x8;

/* @brief  This function will ask underlying NCSI driver
 *         to send an OEM command (command type 0x50) with
 *         the specified payload as the OEM data.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @param[in] opcode  - NCSI Send Command sub-operation
 * @param[in] payload - OEM data to send.
 * @returns 0 on success and negative value for failure.
 */
int sendOemCommand(int ifindex, int package, int channel, int opcode,
                   std::span<const unsigned char> payload);

/* @brief  This function will ask underlying NCSI driver
 *         to set a specific  package or package/channel
 *         combination as the preferred choice.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
int setChannel(int ifindex, int package, int channel);

/* @brief  This function will ask underlying NCSI driver
 *         to clear any preferred setting from the given
 *         interface.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @returns 0 on success and negative value for failure.
 */
int clearInterface(int ifindex);

/* @brief  This function is used to dump all the info
 *         of the package and the channels underlying
 *         the package.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
int getInfo(int ifindex, int package);

/* @brief  This function assigns a mask controlling responses to AEN from a
 * package.
 * @param[in] ifindex - Interface Index.
 * @param[in] mask - A 32-bit mask integer
 * @returns 0 on success and negative value for failure.
 */
int setPackageMask(int ifindex, unsigned int mask);

/* @brief  This function sets the AEN mask for the channels inside the selected
 * package.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] mask - A 32-bit mask integer
 * @returns 0 on success and negative value for failure.
 */
int setChannelMask(int ifindex, int package, unsigned int mask);

/* @brief  This function will ask underlying NCSI driver
 *         to enable or disable Asynchronous Event Notification
 *         (command type 0x8).
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @param[in] AENInt - AEN Interrupt number.
 */
int aenEnable(int ifindex, int package, int channel, int AENInt);

} // namespace ncsi
} // namespace network
} // namespace phosphor
