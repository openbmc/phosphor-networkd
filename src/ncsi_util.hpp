#pragma once

#include <span>

namespace phosphor
{
namespace network
{
namespace ncsi
{

#define NCSI_CMD_GET_VERSION          0x15

//These offsets are relative to the beginning of the respone header
#define NCSIVERSN_OFFSET 20
#define FWV_OFFSET       40
#define PCIDID_OFFSET    44
#define PCIVID_OFFSET    46
#define PCISSID_OFFSET   48
#define PCISVID_OFFSET   50
#define MNFTRID_OFFSET   54

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

// This function is used to retrieve the version id for the package.
// param[in] ifindex - Interface Index.
// param[in] package - NCSI Package.
// param[in] channel - Channel number with in the package.
// returns 0 on success and negative value for failure.
int getVersionID(int ifindex, int package, int channel);

} // namespace ncsi
} // namespace network
} // namespace phosphor
