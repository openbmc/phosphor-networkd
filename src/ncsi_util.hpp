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

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

#define NCSI_CMD_GET_PARAMETRS 0x17

struct NCSIGetParametersResponse{
  uint8_t  macAddrCnt;
  uint16_t reserved0;
  uint8_t  macAddrFlags;
  uint8_t  vlanTagCnt;
  uint8_t  reserved1;
  uint16_t vlanTagFlags;
  uint32_t linkSettings;
  uint32_t broadcastPacketFilterSettings;
  uint32_t configurationFlags;
  uint8_t  vlanMode;
  uint8_t  flowCtrlEnable;
  uint16_t reserved2;
  uint32_t aenControl;
  uint32_t mac1;
  uint32_t mac2;
  uint32_t mac3;
} __attribute__((packed)); // DSP0222 NCSI Spec 8.4.50

/* NC-SI Response Packet */
struct NCSIresponsePacket {
/* end of NC-SI header */
  unsigned short  responseCode;
  unsigned short  reasonCode;
} __attribute__((packed));


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
           parameter.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
int getParam(int ifindex, int package);

/* @brief  This function is used to print the NCSI
 *         parameters.
 * @param[in] rcv_buf - NCSI response buffer.
 * @returns void.
 */
void printNCSIGetParam(unsigned char* rcv_buf);

/* @brief  This function is used to print the NCSI
 *         Response and Reason.
 * @param[in] rcv_buf - NCSI response buffer.
 * @returns void.
 */
void printNCSICompletionCodes(unsigned char* rcv_buf);

} // namespace ncsi
} // namespace network
} // namespace phosphor
