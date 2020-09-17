#include "ncsi_util.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <iomanip>
#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace ncsi
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

using CallBack = int (*)(struct nl_msg* msg, void* arg);

namespace internal
{

struct NCSIPacketHeader
{
    unsigned char MCID;
    unsigned char revision;
    unsigned char reserved;
    unsigned char id;
    unsigned char type;
    unsigned char channel;
    __be16 length;
    __be32 rsvd[2];
};

class Command
{
  private:
    static const std::vector<unsigned char> emptyPayload;

  public:
    Command() = delete;
    ~Command() = default;
    Command(const Command&) = delete;
    Command& operator=(const Command&) = delete;
    Command(Command&&) = default;
    Command& operator=(Command&&) = default;
    Command(int c, int nc = DEFAULT_VALUE,
            const std::vector<unsigned char>& p = emptyPayload) :
        cmd(c),
        ncsi_cmd(nc), payload(p)
    {
    }

    int cmd;
    int ncsi_cmd;
    const std::vector<unsigned char>& payload;
};

const std::vector<unsigned char> Command::emptyPayload;

using nlMsgPtr = std::unique_ptr<nl_msg, decltype(&::nlmsg_free)>;
using nlSocketPtr = std::unique_ptr<nl_sock, decltype(&::nl_socket_free)>;

CallBack infoCallBack = [](struct nl_msg* msg, void* arg) {
    using namespace phosphor::network::ncsi;
    auto nlh = nlmsg_hdr(msg);

    struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
    struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
        {type : NLA_UNSPEC}, {type : NLA_U32}, {type : NLA_NESTED},
        {type : NLA_U32},    {type : NLA_U32},
    };

    struct nlattr* packagetb[NCSI_PKG_ATTR_MAX + 1] = {nullptr};
    struct nla_policy packagePolicy[NCSI_PKG_ATTR_MAX + 1] = {
        {type : NLA_UNSPEC}, {type : NLA_NESTED}, {type : NLA_U32},
        {type : NLA_FLAG},   {type : NLA_NESTED},
    };

    struct nlattr* channeltb[NCSI_CHANNEL_ATTR_MAX + 1] = {nullptr};
    struct nla_policy channelPolicy[NCSI_CHANNEL_ATTR_MAX + 1] = {
        {type : NLA_UNSPEC}, {type : NLA_NESTED}, {type : NLA_U32},
        {type : NLA_FLAG},   {type : NLA_NESTED}, {type : NLA_UNSPEC},
    };

    *(int*)arg = 0;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (!tb[NCSI_ATTR_PACKAGE_LIST])
    {
        std::cerr << "No Packages" << std::endl;
        return -1;
    }

    auto attrTgt = static_cast<nlattr*>(nla_data(tb[NCSI_ATTR_PACKAGE_LIST]));
    if (!attrTgt)
    {
        std::cerr << "Package list attribute is null" << std::endl;
        return -1;
    }

    auto rem = nla_len(tb[NCSI_ATTR_PACKAGE_LIST]);
    nla_for_each_nested(attrTgt, tb[NCSI_ATTR_PACKAGE_LIST], rem)
    {
        ret = nla_parse_nested(packagetb, NCSI_PKG_ATTR_MAX, attrTgt,
                               packagePolicy);
        if (ret < 0)
        {
            std::cerr << "Failed to parse package nested" << std::endl;
            return -1;
        }

        if (packagetb[NCSI_PKG_ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[NCSI_PKG_ATTR_ID]);
            std::cout << "Package has id : " << std::hex << attrID << std::endl;
        }
        else
        {
            std::cout << "Package with no id" << std::endl;
        }

        if (packagetb[NCSI_PKG_ATTR_FORCED])
        {
            std::cout << "This package is forced" << std::endl;
        }

        auto channelListTarget = static_cast<nlattr*>(
            nla_data(packagetb[NCSI_PKG_ATTR_CHANNEL_LIST]));

        auto channelrem = nla_len(packagetb[NCSI_PKG_ATTR_CHANNEL_LIST]);
        nla_for_each_nested(channelListTarget,
                            packagetb[NCSI_PKG_ATTR_CHANNEL_LIST], channelrem)
        {
            ret = nla_parse_nested(channeltb, NCSI_CHANNEL_ATTR_MAX,
                                   channelListTarget, channelPolicy);
            if (ret < 0)
            {
                std::cerr << "Failed to parse channel nested" << std::endl;
                return -1;
            }

            if (channeltb[NCSI_CHANNEL_ATTR_ID])
            {
                auto channel = nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_ID]);
                if (channeltb[NCSI_CHANNEL_ATTR_ACTIVE])
                {
                    std::cout << "Channel Active : " << std::hex << channel
                              << std::endl;
                }
                else
                {
                    std::cout << "Channel Not Active : " << std::hex << channel
                              << std::endl;
                }

                if (channeltb[NCSI_CHANNEL_ATTR_FORCED])
                {
                    std::cout << "Channel is forced" << std::endl;
                }
            }
            else
            {
                std::cout << "Channel with no ID" << std::endl;
            }

            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR])
            {
                auto major =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR]);
                std::cout << "Channel Major Version : " << std::hex << major
                          << std::endl;
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR])
            {
                auto minor =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR]);
                std::cout << "Channel Minor Version : " << std::hex << minor
                          << std::endl;
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_STR])
            {
                auto str =
                    nla_get_string(channeltb[NCSI_CHANNEL_ATTR_VERSION_STR]);
                std::cout << "Channel Version Str :" << str << std::endl;
            }
            if (channeltb[NCSI_CHANNEL_ATTR_LINK_STATE])
            {

                auto link =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_LINK_STATE]);
                std::cout << "Channel Link State : " << std::hex << link
                          << std::endl;
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST])
            {
                std::cout << "Active Vlan ids" << std::endl;
                auto vids = channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    std::cout << "VID : " << id << std::endl;
                    vid = nla_next(vid, &len);
                }
            }
        }
    }
    return (int)NL_SKIP;
};

CallBack sendCallBack = [](struct nl_msg* msg, void* arg) {
    using namespace phosphor::network::ncsi;
    constexpr auto ETHERNET_HEADER_SIZE = 16;
    auto nlh = nlmsg_hdr(msg);
    struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
    static struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
        {type : NLA_UNSPEC}, {type : NLA_U32}, {type : NLA_NESTED},
        {type : NLA_U32},    {type : NLA_U32}, {type : NLA_BINARY},
        {type : NLA_FLAG},   {type : NLA_U32}, {type : NLA_U32},
    };

    *(int*)arg = 0;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (ret)
    {
        std::cerr << "Failed to parse package" << std::endl;
        return ret;
    }

    auto data_len = nla_len(tb[NCSI_ATTR_DATA]) - ETHERNET_HEADER_SIZE;
    unsigned char* data =
        (unsigned char*)nla_data(tb[NCSI_ATTR_DATA]) + ETHERNET_HEADER_SIZE;

    std::cout << "Response : " << std::dec << data_len << " bytes" << std::endl;
    for (auto i = 0; i < data_len; ++i)
    {
        if (i && (!(i % 8)))
        {
            std::cout << std::endl;
        }
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << (int)data[i] << " ";
    }

    std::cout << std::endl;

    return 0;
};

int applyCmd(int ifindex, const Command& cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, int flags = NONE,
             CallBack function = nullptr)
{
    int cb_ret = 0;
    nlSocketPtr socket(nl_socket_alloc(), &::nl_socket_free);
    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        std::cerr << "Failed to open the socket , RC : " << ret << std::endl;
        return ret;
    }

    auto driverID = genl_ctrl_resolve(socket.get(), "NCSI");
    if (driverID < 0)
    {
        std::cerr << "Failed to resolve, RC : " << ret << std::endl;
        return driverID;
    }

    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);

    auto msgHdr = genlmsg_put(msg.get(), 0, 0, driverID, 0, flags, cmd.cmd, 0);
    if (!msgHdr)
    {
        std::cerr << "Unable to add the netlink headers , COMMAND : " << cmd.cmd
                  << std::endl;
        return -1;
    }

    if (package != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_PACKAGE_ID,
                          package);
        if (ret < 0)
        {
            std::cerr << "Failed to set the attribute , RC : " << ret
                      << "PACKAGE " << std::hex << package << std::endl;
            return ret;
        }
    }

    if (channel != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_CHANNEL_ID,
                          channel);
        if (ret < 0)
        {
            std::cerr << "Failed to set the attribute , RC : " << ret
                      << "CHANNEL : " << std::hex << channel << std::endl;
            return ret;
        }
    }

    ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_IFINDEX, ifindex);
    if (ret < 0)
    {
        std::cerr << "Failed to set the attribute , RC : " << ret
                  << "INTERFACE : " << std::hex << ifindex << std::endl;
        return ret;
    }

    if (cmd.ncsi_cmd != DEFAULT_VALUE)
    {
        std::vector<unsigned char> pl(sizeof(NCSIPacketHeader) +
                                      cmd.payload.size());
        NCSIPacketHeader* hdr = (NCSIPacketHeader*)pl.data();

        std::copy(cmd.payload.begin(), cmd.payload.end(),
                  pl.begin() + sizeof(NCSIPacketHeader));

        hdr->type = cmd.ncsi_cmd;
        hdr->length = htons(cmd.payload.size());

        ret = nla_put(msg.get(), ncsi_nl_attrs::NCSI_ATTR_DATA, pl.size(),
                      pl.data());
        if (ret < 0)
        {
            std::cerr << "Failed to set the data attribute, RC : " << ret
                      << std::endl;
            return ret;
        }

        nl_socket_disable_seq_check(socket.get());
    }

    if (function)
    {
        cb_ret = 1;

        // Add a callback function to the socket
        nl_socket_modify_cb(socket.get(), NL_CB_VALID, NL_CB_CUSTOM, function,
                            &cb_ret);
    }

    ret = nl_send_auto(socket.get(), msg.get());
    if (ret < 0)
    {
        std::cerr << "Failed to send the message , RC : " << ret << std::endl;
        return ret;
    }

    do
    {
        ret = nl_recvmsgs_default(socket.get());
        if (ret < 0)
        {
            std::cerr << "Failed to receive the message , RC : " << ret
                      << std::endl;
            break;
        }
    } while (cb_ret);

    return ret;
}

} // namespace internal

int sendCommand(int ifindex, int package, int channel, int cmd,
                const std::vector<unsigned char>& payload)
{
    std::cout << "Send Command : " << std::hex << cmd
              << ", CHANNEL : " << std::hex << channel
              << ", PACKAGE : " << std::hex << package
              << ", IFINDEX: " << std::hex << ifindex << std::endl;
    if (!payload.empty())
    {
        std::cout << "Payload : ";
        for (auto& i : payload)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)i
                      << " ";
        }
        std::cout << std::endl;
    }

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, cmd, payload),
        package, channel, NONE, internal::sendCallBack);
}

int setChannel(int ifindex, int package, int channel)
{
    std::cout << "Set Channel : " << std::hex << channel
              << ", PACKAGE : " << std::hex << package
              << ", IFINDEX :  " << std::hex << ifindex << std::endl;
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_SET_INTERFACE),
        package, channel);
}

int clearInterface(int ifindex)
{
    std::cout << "ClearInterface , IFINDEX :" << std::hex << ifindex
              << std::endl;
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_CLEAR_INTERFACE));
}

int getInfo(int ifindex, int package)
{
    std::cout << "Get Info , PACKAGE :  " << std::hex << package
              << ", IFINDEX :  " << std::hex << ifindex << std::endl;
    if (package == DEFAULT_VALUE)
    {
        return internal::applyCmd(
            ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_PKG_INFO),
            package, DEFAULT_VALUE, NLM_F_DUMP, internal::infoCallBack);
    }
    else
    {
        return internal::applyCmd(ifindex, ncsi_nl_commands::NCSI_CMD_PKG_INFO,
                                  package, DEFAULT_VALUE, NONE,
                                  internal::infoCallBack);
    }
}

} // namespace ncsi
} // namespace network
} // namespace phosphor
