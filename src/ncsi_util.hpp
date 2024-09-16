#pragma once

#include <stdint.h>

#include <optional>
#include <span>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
namespace ncsi
{

constexpr auto DEFAULT_VALUE = -1;
constexpr auto NONE = 0;

struct ChannelInfo
{
    uint32_t id;
    bool active;
    bool forced;
    uint32_t version_major, version_minor;
    std::string version;
    uint32_t link_state;
    std::vector<uint16_t> vlan_ids;
};

struct PackageInfo
{
    uint32_t id;
    bool forced;
    std::vector<ChannelInfo> channels;
};

struct InterfaceInfo
{
    std::vector<PackageInfo> packages;
};

struct NCSICommand
{
    /* constructs a message; the payload span is copied into the internal
     * command vector */
    NCSICommand(uint8_t opcode, uint8_t package, std::optional<uint8_t> channel,
                std::span<unsigned char> payload);

    uint8_t getChannel();

    uint8_t opcode;
    uint8_t package;
    std::optional<uint8_t> channel;
    std::vector<unsigned char> payload;
};

struct NCSIResponse
{
    uint8_t opcode;
    uint8_t response, reason;
    std::span<unsigned char> payload;
    std::vector<unsigned char> full_payload;
};

struct Interface
{
    /* @brief  This function will ask underlying NCSI driver
     *         to send an OEM command (command type 0x50) with
     *         the specified payload as the OEM data.
     *         This function talks with the NCSI driver over
     *         netlink messages.
     * @param[in] package - NCSI Package.
     * @param[in] channel - Channel number with in the package.
     * @param[in] opcode  - NCSI Send Command sub-operation
     * @param[in] payload - OEM data to send.
     * @returns the NCSI response message to this command, or no value on error.
     */
    virtual std::optional<NCSIResponse> sendCommand(NCSICommand& cmd) = 0;

    /**
     * @brief Create a string representation of this interface
     *
     * @returns a string containing an interface identifier, for logging
     */
    virtual std::string toString() = 0;

    /* virtual destructor for vtable */
    virtual ~Interface() {};
};

std::string to_string(Interface& interface);

struct NetlinkInterface : Interface
{
    /* implementations for Interface */
    std::optional<NCSIResponse> sendCommand(NCSICommand& cmd);
    std::string toString();

    /* @brief  This function will ask underlying NCSI driver
     *         to set a specific  package or package/channel
     *         combination as the preferred choice.
     *         This function talks with the NCSI driver over
     *         netlink messages.
     * @param[in] package - NCSI Package.
     * @param[in] channel - Channel number with in the package.
     * @returns 0 on success and negative value for failure.
     */
    int setChannel(int package, int channel);

    /* @brief  This function will ask underlying NCSI driver
     *         to clear any preferred setting from the interface.
     *         This function talks with the NCSI driver over
     *         netlink messages.
     * @returns 0 on success and negative value for failure.
     */
    int clearInterface();

    /* @brief  This function is used to dump all the info
     *         of the package and the channels underlying
     *         the package, or all packages if DEFAULT_VALUE
     *         is passed
     * @param[in] package - NCSI Package
     * @returns an InterfaceInfo with package data the specified pacakge,
     *          or all packages if none is specified.
     */
    std::optional<InterfaceInfo> getInfo(int package);

    /* @brief  This function assigns a mask controlling responses to AEN from a
     * package.
     * @param[in] mask - A 32-bit mask integer
     * @returns 0 on success and negative value for failure.
     */
    int setPackageMask(unsigned int mask);

    /* @brief  This function sets the AEN mask for the channels inside the
     * selected package.
     * @param[in] package - NCSI Package.
     * @param[in] mask - A 32-bit mask integer
     * @returns 0 on success and negative value for failure.
     */
    int setChannelMask(int package, unsigned int mask);

    NetlinkInterface(int ifindex);

    int ifindex;
};

struct MCTPInterface : Interface
{
    std::optional<NCSIResponse> sendCommand(NCSICommand& cmd);
    std::string toString();

    MCTPInterface(int net, uint8_t eid);

  private:
    int sd;
    int net;
    uint8_t eid;
};

} // namespace ncsi
} // namespace network
} // namespace phosphor
