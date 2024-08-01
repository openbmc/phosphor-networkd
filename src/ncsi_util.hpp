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

// defined in DSP0222 Table 9
struct NCSIPacketHeader
{
// 16 bytes NC-SI header
    uint8_t MCID;
	// For NC-SI 1.0 spec, this field has to set 0x01
    uint8_t revision;
    uint8_t reserved;// Reserved has to set to 0x00
    uint8_t id;
    uint8_t type;
    uint8_t channel;
	// Payload Length = 12 bits, 4 bits are reserved
    uint16_t length;
    uint32_t rsvd[2];
};


//Get Capabilities Command (0x16)
//DSP0222 NCSI Spec 8.4.45

#define NCSI_GET_CAPABILITIES 0x16

//Get Capabilities Response Structure
//DSP0222 NCSI Spec 8.4.46

struct NCSI_Get_Capabilities_Response {
  uint32_t capabilities_flags;
  uint32_t broadcast_packet_filter_capabilities;
  uint32_t multicast_packet_filter_capabilities;
  uint32_t buffering_capabilities;
  uint32_t aen_control_support;
  uint32_t filter_cnt;
  //uint32_t vlan_filter_cnt:8;
  //uint32_t mixed_filter_cnt:8;
  //uint32_t multicast_filter_cnt:8;
  //uint32_t unicast_filter_cnt:8;
  //uint8_t  vlan_filter_cnt;
  //uint8_t  mixed_filter_cnt;
  //uint8_t  multicast_filter_cnt;
  //uint8_t  unicast_filter_cnt;
  uint16_t reserved;
  //uint8_t  vlan_mode_support;
  //uint8_t  channel_cnt;
  uint16_t  vlan_mode_support:8;
  uint16_t  channel_cnt:8;
};

/* NC-SI Response Packet */
struct NCSI_Response_Packet {
/* end of NC-SI header */
  unsigned short  Response_Code;
  unsigned short  Reason_Code;
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
void print_ncsi_capabilities(unsigned char *rcv_buf);


} // namespace ncsi
} // namespace network
} // namespace phosphor
