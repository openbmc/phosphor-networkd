#pragma once

#include <cstdint>
#include <span>

namespace phosphor
{
namespace network
{
namespace ncsi
{

#define NCSI_CMD_GET_NCSI_STATISTICS 0x19

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

namespace internal
{

struct NCSIPacketHeader
{
    uint8_t MCID;
    uint8_t revision;
    uint8_t reserved;
    uint8_t id;
    uint8_t type;
    uint8_t channel;
    uint16_t length;
    uint32_t rsvd[2];
};

struct NCSIResponsePacketStatus
{
    uint16_t completionCodeResponse;
    uint16_t completionCodeReason;
};

struct NCSIStatsResponse {
  NCSIPacketHeader header;
  NCSIResponsePacketStatus responsePacketStatus;
  uint32_t cmdsRcvd;
  uint32_t ctrlPktsDropped;
  uint32_t cmdTypeErrs;
  uint32_t cmdChksumErrs;
  uint32_t rxPkts;
  uint32_t txPkts;
  uint32_t aensSent;
}; // DSP0222 NCSI Spec 8.4.52

} // namespace internal

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

/* @brief  This function will ask underlying NCSI driver
 *         to get info on NCSI statistics for the channel
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
int getNCSIStats(int ifindex, int package, int channel);

} // namespace ncsi
} // namespace network
} // namespace phosphor
