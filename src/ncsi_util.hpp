#pragma once

#include <span>

namespace phosphor
{
namespace network
{
namespace ncsi
{

// NCSI RESPONSE PACKET TYPE
// Response packet type for Get Link Status
#define NCSI_CMD_GET_LINK_STATUS_RESP 0x8a

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

/* @brief  This function will ask underlying NCSI driver
 *         to send an NCSI control packet type
 *         with the specified payload as data.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @param[in] ncsiCntl- NCSI control packet type
 * @param[in] payload - data to send.
 * @returns 0 on success and negative value for failure.
 */
int sendControlPacket(int ifindex, int package, int channel, int ncsiCntl,
                      std::span<const unsigned char> payload);

/* @brief  This function is used to print the NCSI
 *         Response for particular response packet
 *         type
 * @param[in] ncsiRespType - NCSI Response packet type.
 * @param[in] ncsiRespLen - NCSI Response Message length..
 * @param[in] respBuf - NCSI response buffer.
 * @returns 0 on success and negative value for failure.
 */
int printNCSIResponse(int ncsiRespType, int ncsiRespLen,
                      unsigned char* respBuf);

/* @brief  This function is used to print the NCSI
 *         Response and Reason completion codes
 * @param[in] respBufCode - NCSI response buffer.
 */
void printCompletionCodes(unsigned char* respBufCode);

/* @brief  This function is used to print the NCSI
 *         Link status related info
 * @param[in] msgdata - NCSI response message data.
 */
void printLinkStatus(unsigned char* msgdata);

} // namespace ncsi
} // namespace network
} // namespace phosphor
