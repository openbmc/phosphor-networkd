#pragma once

#include "ncsi_util.hpp"

#include <linux/ncsi.h>

#include <cstdint>
#include <span>
#include <string>

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{
struct setMacAddrData
{
    uint8_t macAddr[6];
    uint8_t macAddrNum;
    uint8_t macAddrFlags;
    uint32_t checksum;
    uint8_t padding[18];
};

struct setMacAddrRespData
{
    uint32_t checksum;
    uint8_t padding[22];
};

struct setMacAddrResponse
{
    NCSIPacketHeader ncsiRespHdr;
    ncsiCompletionCodes ncsiCCodes;
    struct setMacAddrRespData macAddrRespData;
};

struct setMacAddressResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint32_t checksum;
    uint8_t pad[22];

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(header, response, reason, checksum, pad[0], pad[1], pad[2], pad[3],
           pad[4], pad[5], pad[6], pad[7], pad[8], pad[9], pad[10], pad[11],
           pad[12], pad[13], pad[14], pad[15], pad[16], pad[17], pad[18],
           pad[19], pad[20], pad[21]);
    }
};

} // namespace internal

/* @brief  This function sets the mac address for a
 *         specific interface & channel
 *         the package.
 * @param[in] ifindex - Interface Index.
 * @param[in] channel - channel
 * @param[in] macAddr - the new mac address
 * @returns 0 on success and negative value for failure.
 */
int setMacAddr(int ifindex, int package, int channel,
               const std::string& macAddr, const uint8_t& filter,
               const uint8_t& maFlags);
} // namespace ncsi
} // namespace network
} // namespace phosphor
