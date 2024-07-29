#include "ncsi_util_getvid.hpp"

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
struct versionIdData
{
    uint8_t ncsiVersion[8];
    uint8_t firmwareName[12];
    uint32_t firmwareVersion;
    uint16_t pciDevId;
    uint16_t pciVenId;
    uint16_t pciSSID;
    uint16_t pciSubVenId;
    uint32_t manufacturerId;
    uint32_t checksum;
};
struct getVersionIdResponse
{
    NCSIPacketHeader linkRespHdr;
    ncsiCompletionCodes linkStatCodes;
    struct versionIdData versnIdData;
};
std::string ncsiBCDToStr(const std::vector<uint8_t>& rawBCD)
{
    uint8_t byte = 0;
    uint8_t nibble = 0;
    std::string bcdStr{};
    for (auto i = 0; i <= 2; i++)
    {
        byte = rawBCD.at(i);
        nibble = (byte >> 4);
        if (nibble < 10)
        {
            bcdStr.push_back(static_cast<char>(nibble + 0x30));
        }
        nibble = (byte & 0x0F);
        if (nibble < 10)
        {
            bcdStr.push_back(static_cast<char>(nibble + 0x30));
        }
        bcdStr.push_back('.');
    }
    // Step on the trailing dot ...
    bcdStr.back() = rawBCD.at(3);
    bcdStr.push_back(rawBCD.at(7));
    return bcdStr;
}

CallBack getVersionIdCallBack = [](struct nl_msg* msg, void* arg) {
    std::span<const unsigned char> payload;
    auto ret = getNcsiCommandPayload(msg, arg, payload);
    if (ret != 0)
    {
        return ret;
    }
    std::vector<unsigned char> payloadVec(payload.begin(), payload.end());
    auto data_dx = sizeof(struct NCSIPacketHeader) +
                   sizeof(struct ncsiCompletionCodes);
    std::vector<uint8_t> rawBCD(&payloadVec[data_dx], &payloadVec[data_dx] + 8);
    lg2::debug("NCSI version (BCD): {NCSI_VERSION}", "NCSI_VERSION",
               ncsiBCDToStr(rawBCD));
    data_dx += 20; // Skip ncsiVersion & fw-string
    auto fwVersn = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(&payloadVec[data_dx]), 4);
    lg2::debug("Firmware version: {FW_VERSION_ID}", "FW_VERSION_ID",
               toHexStr(fwVersn));
    data_dx += 4;
    lg2::debug("PciVendor: {PCI_VENDOR_ID}", "PCI_VENDOR_ID", lg2::hex,
               ntohs(*(reinterpret_cast<uint16_t*>(&payloadVec[data_dx]))));
    data_dx += sizeof(uint16_t);
    lg2::debug("PciDevice: {PCI_DEVICE_ID}", "PCI_DEVICE_ID", lg2::hex,
               ntohs(*(reinterpret_cast<uint16_t*>(&payloadVec[data_dx]))));
    // Skip Dev-id, Subsys-id, Sub-vendor-id
    data_dx += (sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t));
    lg2::debug("IANA Manufacturer Id: {MANUFACTURER_ID}", "MANUFACTURER_ID",
               ntohl(*(reinterpret_cast<uint32_t*>(&payloadVec[data_dx]))));
    return 0;
};
} // namespace internal

int getVersionID(int ifindex, int package, int channel)
{
    constexpr auto ncsi_cmd = 0x15;
    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, ncsi_cmd),
        package, channel, NONE, internal::getVersionIdCallBack);
}
} // namespace ncsi
} // namespace network
} // namespace phosphor
