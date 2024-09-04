#pragma once

#include "ncsi_util.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{

struct DisableVlanResponsePacket
{
    NCSIPacketHeader header;
    uint16_t response;
    uint16_t reason;
    uint32_t checksum;
    uint8_t pad[22];

    template <class Archive>
    void serialize(Archive &ar)
    {
        ar(header, response, reason, checksum, pad[0], pad[1], pad[2], pad[3], 
           pad[4], pad[5], pad[6], pad[7], pad[8], pad[9], pad[10], 
           pad[11], pad[12], pad[13], pad[14], pad[15], pad[16], 
           pad[17], pad[18], pad[19], pad[20], pad[21]);
    }
};

} // namespace internal

    /* @brief This function will ask underlying NCSI driver
    *        to send a Disable VLAN (command type 0x0D) 
    *        This function talks with the NCSI driver over
    *        netlink messages.
    * @param[in] ifindex - Interface Index.
    * @param[in] package - NCSI Package.
    * @param[in] channel - Channel number with in the package.
    * @returns 0 on success and negative value for failure.
    */
    int disableVlan(int ifindex, int package, int channel);
} // namespace ncsi
} // namespace network
} // namespace phosphor
