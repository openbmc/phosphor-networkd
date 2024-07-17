#pragma once

#include <span>
#include <cstdint>

namespace phosphor
{
namespace network
{
namespace ncsi
{

#define   NCSI_GET_CONTROLLER_PACKET_STATISTICS 0x18

typedef struct {
  uint32_t counters_cleared_from_last_read_MSB;
  uint32_t counters_cleared_from_last_read_LSB;
  uint64_t total_bytes_rcvd;
  uint64_t total_bytes_tx;
  uint64_t total_unicast_pkts_rcvd;
  uint64_t total_multicast_pkts_rcvd;
  uint64_t total_broadcast_pkts_rcvd;
  uint64_t total_unicast_pkts_tx;
  uint64_t total_multicast_pkts_tx;
  uint64_t total_broadcast_pkts_tx;
  uint32_t fcs_receive_errs;
  uint32_t alignment_errs;
  uint32_t false_carrier_detections;
  uint32_t runt_pkts_rcvd;
  uint32_t jabber_pkts_rcvd;
  uint32_t pause_xon_frames_rcvd;
  uint32_t pause_xoff_frames_rcvd;
  uint32_t pause_xon_frames_tx;
  uint32_t pause_xoff_frames_tx;
  uint32_t single_collision_tx_frames;
  uint32_t multiple_collision_tx_frames;
  uint32_t late_collision_frames;
  uint32_t excessive_collision_frames;
  uint32_t control_frames_rcvd;
  uint32_t rx_frame_64;
  uint32_t rx_frame_65_127;
  uint32_t rx_frame_128_255;
  uint32_t rx_frame_256_511;
  uint32_t rx_frame_512_1023;
  uint32_t rx_frame_1024_1522;
  uint32_t rx_frame_1523_9022;
  uint32_t tx_frame_64;
  uint32_t tx_frame_65_127;
  uint32_t tx_frame_128_255;
  uint32_t tx_frame_256_511;
  uint32_t tx_frame_512_1023;
  uint32_t tx_frame_1024_1522;
  uint32_t tx_frame_1523_9022;
  uint64_t valid_bytes_rcvd;
  uint32_t err_runt_packets_rcvd;
  uint32_t err_jabber_packets_rcvd;
} __attribute__((packed)) NCSI_Controller_Packet_Stats_Response;

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;






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
void print_ncsi_controller_stats(unsigned char *rcv_buf);

} // namespace ncsi
} // namespace network
} // namespace phosphor
