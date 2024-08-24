#include "ncsi_util_setmac.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <cereal/archives/binary.hpp>
#include <cereal/types/vector.hpp>
#include <phosphor-logging/lg2.hpp>

#include <sstream>

namespace phosphor
{
namespace network
{
namespace ncsi
{
using CallBack = int (*)(struct nl_msg* msg, void* arg);

namespace internal
{

int displayResponseInfo(NCSIPacketHeader* respInfo)
{
    unsigned char* respData = reinterpret_cast<unsigned char*>(respInfo);
    respData += 4;
    uint8_t cmtype = *respData;

    respData = reinterpret_cast<unsigned char*>(respInfo);
    respData += sizeof(NCSIPacketHeader);
    uint16_t responseCode = (*(reinterpret_cast<uint16_t*>(respData)));

    respData += sizeof(uint16_t);
    uint16_t reason = (*(reinterpret_cast<uint16_t*>(respData)));

    lg2::debug("Display Response Data: CTL_MSG_TYPE:{CTL_MSG_TYPE}"
               " RESPONSE_CODE:{RESPONSE_CODE} REASON:{REASON}",
               "CTL_MSG_TYPE", lg2::hex, cmtype, "RESPONSE_CODE", lg2::hex,
               responseCode, "REASON", lg2::hex, reason);

    return 0;
}

CallBack setMacAddressCallBack = [](struct nl_msg* msg, void* arg) {
    std::span<const unsigned char> payload;
    auto ret = getNcsiCommandPayload(msg, arg, payload);

    if (ret != 0)
    {
        return ret;
    }

    std::vector<unsigned char> payloadVec(payload.begin(), payload.end());

    std::istringstream iss(std::string(payloadVec.begin(), payloadVec.end()));
    cereal::BinaryInputArchive ar(iss);
    setMacAddressResponsePacket packet;
    ar(packet);

    auto type = packet.header.type;
    lg2::debug("Set MAC Address Response type : {RESPONSE_TYPE}",
               "RESPONSE_TYPE", lg2::hex, type);

    auto headerLength = htons(packet.header.length);
    lg2::debug("Set MAC Address Response length : {RESPONSE_LEN}",
               "RESPONSE_LEN", lg2::hex, headerLength);

    auto response = ntohs(packet.response);
    auto reason = ntohs(packet.reason);

    lg2::debug("Set MAC Address Response : {RESPONSE} Reason : {REASON}",
               "RESPONSE", lg2::hex, response, "REASON", lg2::hex, reason);

    return 0;
};
} // namespace internal

void asciiToPackedHex(const std::string& asciHexDigits,
                      std::vector<uint8_t> packedHex)
{
    uint8_t hi_nbl = 0;
    uint8_t lo_nbl = 0;
    uint8_t nibble = 0;
    uint16_t i = 0;

    for (unsigned char byte : asciHexDigits)
    {
        nibble = byte & 0x0F;
        if (byte > 0x40)
        {
            nibble += 9; // 0x1 --> 0xA; 0x2 --> 0xB
        }

        if ((i % 2) == 0)
        {
            hi_nbl = nibble;
        }
        else
        {
            lo_nbl = nibble;
            packedHex.push_back((hi_nbl << 4) + lo_nbl);
        }

        i++;
    }
}

int setMacAddr(int ifindex, int package, int channel,
               const std::string& macAddr, const uint8_t& filter,
               const uint8_t& macAddrFlags)
{
    constexpr auto ncsi_cmd = 0x0E;

    struct internal::setMacAddrData strMacAddrData;
    size_t setSz = sizeof(struct internal::setMacAddrData);
    unsigned char* pStr = reinterpret_cast<unsigned char*>(&strMacAddrData);

    lg2::debug("Set Mac Address: INTERFACE_INDEX:{INTERFACE_INDEX}"
               " MAC_ADDRESS:{MAC_ADDRESS} FILTER:{FILTER} FLAGS:{FLAGS}",
               "INTERFACE_INDEX", ifindex, "MAC_ADDRESS", macAddr, "FILTER",
               filter, "FLAGS", lg2::hex, macAddrFlags);

    std::fill(reinterpret_cast<char*>(pStr),
              reinterpret_cast<char*>(pStr + setSz), 0);
    std::vector<uint8_t> macAddrVctr(strMacAddrData.macAddr,
                                     strMacAddrData.macAddr + 6);
    asciiToPackedHex(macAddr, macAddrVctr);
    strMacAddrData.macAddrNum = filter;
    strMacAddrData.macAddrFlags = macAddrFlags;

    std::span<const unsigned char> payload(pStr, setSz);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, ncsi_cmd,
                          payload),
        package, channel, NONE, internal::setMacAddressCallBack);
}
} // namespace ncsi
} // namespace network
} // namespace phosphor
