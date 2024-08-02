#pragma once

#include <span>
#include <cstdint>

namespace phosphor
{
namespace network
{
namespace ncsi
{

#define NCSI_MAX_PAYLOAD 1480 // maximum payload size
// max ethernet frame size = 1518
// ethernet headr (14) + nc-si header (16) + nc-si payload (1480) + nc-si checksum (4) + 4 (FCS) = 1518

// Maximum NC-SI netlink response
 // Kernel sends all frame data after ethernet header, including FCS,
 // as netlink response data.
 //    nc-si header (16) + nc-si payload (1480) + nc-si checksum (4) + FCS (4) = 1504
 //
#define NCSI_MAX_NL_RESPONSE (sizeof(NCSIPacketHeader) + NCSI_MAX_PAYLOAD + 4 + 4)


//NCSI OEM Commands
#define NCSI_OEM_CMD 0x50
#define NUM_NCSI_CDMS 27

enum {
  RESP_COMMAND_COMPLETED = 0,
  RESP_COMMAND_FAILED,
  RESP_COMMAND_UNAVAILABLE,
  RESP_COMMAND_UNSUPPORTED,
  RESP_MAX, /* max number of response code. */
};


#define NUM_NCSI_REASON_CODE             8
#define REASON_NO_ERROR             0x0000
#define REASON_INTF_INIT_REQD       0x0001
#define REASON_PARAM_INVALID        0x0002
#define REASON_CHANNEL_NOT_RDY      0x0003
#define REASON_PKG_NOT_RDY          0x0004
#define REASON_INVALID_PAYLOAD_LEN  0x0005
#define REASON_INFO_NOT_AVAIL       0x0006
#define REASON_UNKNOWN_CMD_TYPE     0x7FFF

//Get Capabilities Command (0x16)
//DSP0222 NCSI Spec 8.4.45

#define NCSI_GET_CAPABILITIES 0x16

//Get Capabilities Response Structure
//DSP0222 NCSI Spec 8.4.46

struct NCSIgetCapabilitiesResponse {
  uint32_t capabilitiesFlags;
  uint32_t broadcastPacketFilterCapabilities;
  uint32_t multicastPacketFilterCapabilities;
  uint32_t bufferingCapabilities;
  uint32_t aenControlSupport;
  uint32_t filterCnt;
  uint16_t reserved;
  uint16_t vlanModeSupport:8;
  uint16_t channelCnt:8;
};

/* NC-SI Response Packet */
struct NCSIresponsePacket {
/* end of NC-SI header */
  unsigned short  responseCode;
  unsigned short  reasonCode;
};

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
           capabilities.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
int getCapabilities(int ifindex, int package);

/* @brief  This function is used to print the NCSI
 *         Capabilities information.
 * @param[in] rcv_buf - NCSI response buffer.
 * @returns void.
 */
void printNcsiCapabilities(unsigned char *rcvBuf);

} // namespace ncsi
} // namespace network
} // namespace phosphor
