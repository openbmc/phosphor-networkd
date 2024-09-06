#include "ncsi_util_getmac.hpp"

#include <linux/ncsi.h>

#include <phosphor-logging/lg2.hpp>

namespace phosphor
{
namespace network
{
namespace ncsi
{
using CallBack = int (*)(struct nl_msg* msg, void* arg);

namespace internal
{
struct macAddress
{
  uint8_t Bytes[6];
};

struct getMacAddressesResponse
{
    NCSIPacketHeader linkRespHdr;
    ncsiCompletionCodes linkStatCodes;
    uint8_t numMacAddrs;
    uint8_t Reserved[3];
    struct macAddress macAddresses[10];
};

void printMacAddress(struct macAddress* macAddr)
{
    uint8_t byte = 0;
    uint8_t nibble = 0;
    std::string printMac{};

    for (auto i = 0; i <= 5; i++)
    {
        byte = macAddr->Bytes[i];
        nibble = (byte >> 4);
        if (nibble < 10)
        {
            printMac.push_back(static_cast<char>(nibble + 0x30));
        }
        else
        {
            printMac.push_back(static_cast<char>((nibble-9) + 0x40));
        }

        nibble = (byte & 0x0F);
        if (nibble < 10)
        {
            printMac.push_back(static_cast<char>(nibble + 0x30));
        }
        else
        {
            printMac.push_back(static_cast<char>((nibble-9) + 0x40));
        }

        printMac.push_back(':');
    }

    // Erase the trailing colon ...
    printMac.back() = ' ';

   lg2::debug("MAC_ADDRESS: {MAC_ADDRESS}", "MAC_ADDRESS", printMac);
}

CallBack getChnlMacAddrsCallBack = [](struct nl_msg* msg, void* arg) {
    std::span<const unsigned char> payload;
    auto ret = getNcsiCommandPayload(msg, arg, payload);

    if (ret != 0)
    {
        return ret;
    }

    std::vector<unsigned char> payloadVec(payload.begin(), payload.end());

    auto data_dx = sizeof(struct NCSIPacketHeader) +
                   sizeof(struct ncsiCompletionCodes);

    uint8_t numAddrs = payloadVec[data_dx];
    lg2::debug("NUM_ADDRESSES: {NUM_ADDRESSES}", "NUM_ADDRESSES", numAddrs);

    data_dx += 4;
    for (auto i=0; i < numAddrs; i++)
    {
        printMacAddress(reinterpret_cast<struct macAddress*>(
              &payloadVec[data_dx]));
        data_dx += sizeof(struct macAddress);
    }

    return 0;
};
} // namespace internal

int getChnlMacAddrs(int ifindex, int package, int channel)
{
   constexpr auto ncsi_cmd = 0x58; //DMTF DSP0222 2023-08-25

   lg2::debug(
       "Get Channel Mac Addresses , INTERFACE_INDEX: {INTERFACE_INDEX} PACKAGE: {PACKAGE} CHANNEL: {CHANNEL}",
       "INTERFACE_INDEX", lg2::hex, ifindex, "PACKAGE", lg2::hex, package,
       "CHANNEL", lg2::hex, channel);

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, ncsi_cmd),
        package, channel, NONE, internal::getChnlMacAddrsCallBack);
}
} // namespace ncsi
} // namespace network
} // namespace phosphor
