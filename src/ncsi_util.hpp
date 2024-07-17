#pragma once

#include <cstdint>
#include <span>

namespace phosphor {
namespace network {
namespace ncsi {

#define NCSI_CMD_GET_CONTROLLER_PACKET_STATISTICS 0x18

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;
struct NCSIControllerPacketStatsResponse {
  uint32_t countersClearedFromLastReadMSB;
  uint32_t countersClearedFromLastReadLSB;
  uint64_t totalBytesRcvd;
  uint64_t totalBytesTx;
  uint64_t totalUnicastPktsRcvd;
  uint64_t totalMulticastPktsRcvd;
  uint64_t totalBroadcastPktsRcvd;
  uint64_t totalUnicastPktsTx;
  uint64_t totalMulticastPktsTx;
  uint64_t totalBroadcastPktsTx;
  uint32_t fcsReceiveErrs;
  uint32_t alignmentErrs;
  uint32_t falseCarrierDetections;
  uint32_t runtPktsRcvd;
  uint32_t jabberPktsRcvd;
  uint32_t pauseXOnFramesRcvd;
  uint32_t pauseXOffFramesRcvd;
  uint32_t pauseXOnFramesTx;
  uint32_t pauseXOffFramesTx;
  uint32_t singleCollisionTxFrames;
  uint32_t multipleCollisionTxFrames;
  uint32_t lateCollisionFrames;
  uint32_t excessiveCollisionFrames;
  uint32_t controlFramesRcvd;
  uint32_t rxFrame_64;
  uint32_t rxFrame_65_127;
  uint32_t rxFrame_128_255;
  uint32_t rxFrame_256_511;
  uint32_t rxFrame_512_1023;
  uint32_t rxFrame_1024_1522;
  uint32_t rxFrame_1523_9022;
  uint32_t txFrame_64;
  uint32_t txFrame_65_127;
  uint32_t txFrame_128_255;
  uint32_t txFrame_256_511;
  uint32_t txFrame_512_1023;
  uint32_t txFrame_1024_1522;
  uint32_t txFrame_1523_9022;
  uint64_t validBytesRcvd;
  uint32_t errRuntPacketsRcvd;
  uint32_t errJabberPacketsRcvd;
}; // DSP0222 NCSI Spec 8.4.50

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

/* @brief  This function is used to get NCSI controller
           packet stats.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
int getStats(int ifindex, int package);

/* @brief  This function is used to print the NCSI
 *         controller packet stats.
 * @param[in] rcv_buf - NCSI response buffer.
 * @returns void.
 */
void printNCSIControllerStats(unsigned char *rcv_buf);

/* @brief  This function is used to print the Response
 *         and Reason.
 * @param[in] rcv_buf - NCSI response buffer.
 * @returns void.
 */
void printNCSICompletionCodes(unsigned char *rcv_buf);

} // namespace ncsi
} // namespace network
} // namespace phosphor
