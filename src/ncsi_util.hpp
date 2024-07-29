#pragma once

#include <netlink/netlink.h>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <stdplus/numeric/str.hpp>

namespace phosphor
{
namespace network
{
namespace ncsi
{
using CallBack = int (*)(struct nl_msg* msg, void* arg);

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

stdplus::StrBuf toHexStr(std::span<const uint8_t> c) noexcept;

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

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(MCID, revision, reserved, id, type, channel, length, rsvd[0],
           rsvd[1]);
    }
};

struct ncsiCompletionCodes
{
    uint16_t completionCodeResponse;
    uint16_t completionCodeReason;
};

class Command
{
  public:
    Command() = delete;
    ~Command() = default;
    Command(const Command&) = delete;
    Command& operator=(const Command&) = delete;
    Command(Command&&) = default;
    Command& operator=(Command&&) = default;
    Command(
        int ncsiCmd, int operation = DEFAULT_VALUE,
        std::span<const unsigned char> p = std::span<const unsigned char>()) :
        ncsi_cmd(ncsiCmd), operation(operation), payload(p)
    {}

    int ncsi_cmd;
    int operation;
    std::span<const unsigned char> payload;
};

int getNcsiCommandPayload(struct nl_msg* msg, void* arg,
                          std::span<const unsigned char>& payload);

int applyCmd(int ifindex, const Command& cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, int flags = NONE,
             CallBack function = nullptr);
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
} // namespace ncsi
} // namespace network
} // namespace phosphor
