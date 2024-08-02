#include "ncsi_util.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <iomanip>
#include <iostream>
#include <vector>
using namespace std;

namespace phosphor
{
namespace network
{
namespace ncsi
{

using CallBack = int (*)(struct nl_msg* msg, void* arg);

static stdplus::StrBuf toHexStr(std::span<const uint8_t> c) noexcept
{
    stdplus::StrBuf ret;
    if (c.empty())
    {
        return ret;
    }
    stdplus::IntToStr<16, uint8_t> its;
    auto oit = ret.append(c.size() * 3);
    auto cit = c.begin();
    oit = its(oit, *cit++, 2);
    for (; cit != c.end(); ++cit)
    {
        *oit++ = ' ';
        oit = its(oit, *cit, 2);
    }
    *oit = 0;
    return ret;
}

namespace internal
{

// defined in DSP0222 Table 9
struct NCSIPacketHeader
{
// 16 bytes NC-SI header
    uint8_t MCID;
// For NC-SI 1.0 spec, this field has to set 0x01
    uint8_t revision;
    uint8_t reserved;// Reserved has to set to 0x00
    uint8_t id;
    uint8_t type;
    uint8_t channel;
// Payload Length = 12 bits, 4 bits are reserved
    uint16_t length;
    uint32_t rsvd[2];
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
        ncsi_cmd(ncsiCmd),
        operation(operation), payload(p)
    {}

    int ncsi_cmd;
    int operation;
    std::span<const unsigned char> payload;
};

using nlMsgPtr = std::unique_ptr<nl_msg, decltype(&::nlmsg_free)>;
using nlSocketPtr = std::unique_ptr<nl_sock, decltype(&::nl_socket_free)>;

CallBack infoCallBack = [](struct nl_msg* msg, void* arg) {
    using namespace phosphor::network::ncsi;
    auto nlh = nlmsg_hdr(msg);

    struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
    struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_U32, 0, 0}, {NLA_NESTED, 0, 0},
        {NLA_U32, 0, 0},    {NLA_U32, 0, 0},
    };

    struct nlattr* packagetb[NCSI_PKG_ATTR_MAX + 1] = {nullptr};
    struct nla_policy packagePolicy[NCSI_PKG_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_NESTED, 0, 0}, {NLA_U32, 0, 0},
        {NLA_FLAG, 0, 0},   {NLA_NESTED, 0, 0},
    };

    struct nlattr* channeltb[NCSI_CHANNEL_ATTR_MAX + 1] = {nullptr};
    struct nla_policy channelPolicy[NCSI_CHANNEL_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_NESTED, 0, 0}, {NLA_U32, 0, 0},
        {NLA_FLAG, 0, 0},   {NLA_NESTED, 0, 0}, {NLA_UNSPEC, 0, 0},
    };

    *(int*)arg = 0;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (!tb[NCSI_ATTR_PACKAGE_LIST])
    {
        lg2::error("No Packages");
        return -1;
    }

    auto attrTgt = static_cast<nlattr*>(nla_data(tb[NCSI_ATTR_PACKAGE_LIST]));
    if (!attrTgt)
    {
        lg2::error("Package list attribute is null");
        return -1;
    }

    auto rem = nla_len(tb[NCSI_ATTR_PACKAGE_LIST]);
    nla_for_each_nested(attrTgt, tb[NCSI_ATTR_PACKAGE_LIST], rem)
    {
        ret = nla_parse_nested(packagetb, NCSI_PKG_ATTR_MAX, attrTgt,
                               packagePolicy);
        if (ret < 0)
        {
            lg2::error("Failed to parse package nested");
            return -1;
        }

        if (packagetb[NCSI_PKG_ATTR_ID])
        {
            auto attrID = nla_get_u32(packagetb[NCSI_PKG_ATTR_ID]);
            lg2::debug("Package has id : {ATTR_ID}", "ATTR_ID", lg2::hex,
                       attrID);
        }
        else
        {
            lg2::debug("Package with no id");
        }

        if (packagetb[NCSI_PKG_ATTR_FORCED])
        {
            lg2::debug("This package is forced");
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
                lg2::error("Failed to parse channel nested");
                return -1;
            }

            if (channeltb[NCSI_CHANNEL_ATTR_ID])
            {
                auto channel = nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_ID]);
                if (channeltb[NCSI_CHANNEL_ATTR_ACTIVE])
                {
                    lg2::debug("Channel Active : {CHANNEL}", "CHANNEL",
                               lg2::hex, channel);
                }
                else
                {
                    lg2::debug("Channel Not Active : {CHANNEL}", "CHANNEL",
                               lg2::hex, channel);
                }

                if (channeltb[NCSI_CHANNEL_ATTR_FORCED])
                {
                    lg2::debug("Channel is forced");
                }
            }
            else
            {
                lg2::debug("Channel with no ID");
            }

            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR])
            {
                auto major =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MAJOR]);
                lg2::debug("Channel Major Version : {CHANNEL_MAJOR_VERSION}",
                           "CHANNEL_MAJOR_VERSION", lg2::hex, major);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR])
            {
                auto minor =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_VERSION_MINOR]);
                lg2::debug("Channel Minor Version : {CHANNEL_MINOR_VERSION}",
                           "CHANNEL_MINOR_VERSION", lg2::hex, minor);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VERSION_STR])
            {
                auto str =
                    nla_get_string(channeltb[NCSI_CHANNEL_ATTR_VERSION_STR]);
                lg2::debug("Channel Version Str : {CHANNEL_VERSION_STR}",
                           "CHANNEL_VERSION_STR", str);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_LINK_STATE])
            {
                auto link =
                    nla_get_u32(channeltb[NCSI_CHANNEL_ATTR_LINK_STATE]);
                lg2::debug("Channel Link State : {LINK_STATE}", "LINK_STATE",
                           lg2::hex, link);
            }
            if (channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST])
            {
                lg2::debug("Active Vlan ids");
                auto vids = channeltb[NCSI_CHANNEL_ATTR_VLAN_LIST];
                auto vid = static_cast<nlattr*>(nla_data(vids));
                auto len = nla_len(vids);
                while (nla_ok(vid, len))
                {
                    auto id = nla_get_u16(vid);
                    lg2::debug("VID : {VLAN_ID}", "VLAN_ID", id);
                    vid = nla_next(vid, &len);
                }
            }
        }
    }
    return (int)NL_SKIP;
};

// NCSI response code string
const char *ncsiRespString[RESP_MAX] = {
  "COMMAND_COMPLETED",
  "COMMAND_FAILED",
  "COMMAND_UNAVAILABLE",
  "COMMAND_UNSUPPORTED",
};

// NCSI reason code string
const char *ncsiReasonString[NUM_NCSI_REASON_CODE] = {
  "NO_ERROR",
  "INTF_INIT_REQD",
  "PARAM_INVALID",
  "CHANNEL_NOT_RDY",
  "PKG_NOT_RDY",
  "INVALID_PAYLOAD_LEN",
  "INFO_NOT_AVAIL",
  "UNKNOWN_CMD_TYPE",
};

// NCSI command name
const char *ncsiCmdString[NUM_NCSI_CDMS] = {
  "CLEAR_INITIAL_STATE",
  "SELECT_PACKAGE",
  "DESELECT_PACKAGE",
  "ENABLE_CHANNEL",
  "DISABLE_CHANNEL",
  "RESET_CHANNEL",
  "ENABLE_CHANNEL_NETWORK_TX",
  "DISABLE_CHANNEL_NETWORK_TX",
  "AEN_ENABLE",
  "SET_LINK",
  "GET_LINK_STATUS",
  "SET_VLAN_FILTER",
  "ENABLE_VLAN",
  "DISABLE_VLAN",
  "SET_MAC_ADDRESS",
  "invalid",  // no command 0x0f
  "ENABLE_BROADCAST_FILTERING",
  "DISABLE_BROADCAST_FILTERING",
  "ENABLE_GLOBAL_MULTICAST_FILTERING",
  "DISABLE_GLOBAL_MULTICAST_FILTERING",
  "SET_NCSI_FLOW_CONTROL",
  "GET_VERSION_ID",
  "GET_CAPABILITIES",
  "GET_PARAMETERS",
  "GET_CONTROLLER_PACKET_STATISTICS",
  "GET_NCSI_STATISTICS",
  "GET_NCSI_PASS_THROUGH_STATISTICS",
};

const char *
ncsiCmdTypeToName(int cmd)
{
  switch (cmd) {
    case NCSI_OEM_CMD:
      return "NCSI_OEM_CMD";
    default:
      if ((cmd < 0) ||
          (cmd >= NUM_NCSI_CDMS) ||
          (ncsiCmdString[cmd] == NULL)) {
        return "unknown_ncsi_cmd";
      } else {
        return ncsiCmdString[cmd];
      }
  }
}

const char *
ncsiCcRespName(int ccResp)
{
  if ((ccResp < 0) ||
      (ccResp >= RESP_MAX) ||
      (ncsiRespString[ccResp] == NULL)) {
    return "unknown_response";
  } else {
    return ncsiRespString[ccResp];
  }
}


const char *
ncsiCcResonName(int ccReason)
{
  switch (ccReason) {
    case REASON_UNKNOWN_CMD_TYPE:
      return "UNKNOWN_CMD_TYPE";
    default:
      if ((ccReason < 0) ||
          (ccReason >= NUM_NCSI_REASON_CODE) ||
          (ncsiReasonString[ccReason] == NULL)) {
        return "unknown_reason";
      } else {
        return ncsiReasonString[ccReason];
      }
  }
}

int
getCmdStatus(NCSIresponsePacket *rcvBuf)
{
  int ccResp = rcvBuf->responseCode;

  return (ccResp);
}

void printNcsiCompletionCodes(NCSIresponsePacket *rcvBuf)
{
  int ccResp = rcvBuf->responseCode;
  int ccReason = rcvBuf->reasonCode;

  cout<<"NC-SI Command Response:"<<endl;
  cout<<"Response: "<<ncsiCcRespName(ccResp)<<" ("<<"0x"<<hex<<ccResp<<")"<<endl;
  cout<<"Reason: "<<ncsiCcResonName(ccReason)<<" ("<<"0x"<<hex<<ccReason<<")"<<endl;

  return;
}

void
printNcsiResp(unsigned char *data, int dataLen, int cmdSent)
{
  NCSIresponsePacket *rcvBuf = reinterpret_cast<NCSIresponsePacket *>(data);

  cout<<"cmd: "<<ncsiCmdTypeToName(cmdSent)<<"("<<"0x"<<hex<<cmdSent<<")"<<endl;
  printNcsiCompletionCodes(rcvBuf);
  if (getCmdStatus(rcvBuf) != RESP_COMMAND_COMPLETED)
  {
    return;
  }

  dataLen = (dataLen - sizeof(NCSIresponsePacket));
  data=(data + sizeof(NCSIresponsePacket));
    switch (cmdSent) {
     case NCSI_GET_CAPABILITIES:
       printNcsiCapabilities(data);
       break;
    default:
     cout<<"Payload length = "<<dataLen<<endl;
    auto str = toHexStr(std::span<const unsigned char>(data, dataLen));
    lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN", dataLen,
               "DATA", str);
       break;
    };

  return;
}

CallBack sendCallBack = [](struct nl_msg* msg, void* arg) {
    using namespace phosphor::network::ncsi;
    auto nlh = nlmsg_hdr(msg);
    struct nlattr* tb[NCSI_ATTR_MAX + 1] = {nullptr};
    static struct nla_policy ncsiPolicy[NCSI_ATTR_MAX + 1] = {
        {NLA_UNSPEC, 0, 0}, {NLA_U32, 0, 0}, {NLA_NESTED, 0, 0},
        {NLA_U32, 0, 0},    {NLA_U32, 0, 0}, {NLA_BINARY, 0, 0},
        {NLA_FLAG, 0, 0},   {NLA_U32, 0, 0}, {NLA_U32, 0, 0},
    };

    *(int*)arg = 0;

    auto ret = genlmsg_parse(nlh, 0, tb, NCSI_ATTR_MAX, ncsiPolicy);
    if (ret)
    {
        lg2::error("Failed to parse package");
        return ret;
    }

    if (tb[NCSI_ATTR_DATA] == nullptr)
    {
        lg2::error("Response: No data");
        return -1;
    }

    auto dataLen = nla_len(tb[NCSI_ATTR_DATA]) - sizeof(NCSIPacketHeader);
    unsigned char* data = (unsigned char*)nla_data(tb[NCSI_ATTR_DATA]) +
                          sizeof(NCSIPacketHeader);

    // Dump the response to stdout. Enhancement: option to save response data
    auto str = toHexStr(std::span<const unsigned char>(data, dataLen));
    lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN", dataLen,
               "DATA", str);


    NCSIPacketHeader *rcvHdr = reinterpret_cast<NCSIPacketHeader *>(nla_data(tb[NCSI_ATTR_DATA]));
    int cmdSent = ((rcvHdr->type) & 0x7f) ;
     // Print NCSI response..
    printNcsiResp(data,dataLen,cmdSent);
    return 0;
};

int applyCmd(int ifindex, const Command& cmd, int package = DEFAULT_VALUE,
             int channel = DEFAULT_VALUE, int flags = NONE,
             CallBack function = nullptr)
{
    int cb_ret = 0;
    nlSocketPtr socket(nl_socket_alloc(), &::nl_socket_free);
    if (socket == nullptr)
    {
        lg2::error("Unable to allocate memory for the socket");
        return -ENOMEM;
    }

    auto ret = genl_connect(socket.get());
    if (ret < 0)
    {
        lg2::error("Failed to open the socket , RC : {RC}", "RC", ret);
        return ret;
    }

    auto driverID = genl_ctrl_resolve(socket.get(), "NCSI");
    if (driverID < 0)
    {
        lg2::error("Failed to resolve, RC : {RC}", "RC", ret);
        return driverID;
    }

    nlMsgPtr msg(nlmsg_alloc(), &::nlmsg_free);
    if (msg == nullptr)
    {
        lg2::error("Unable to allocate memory for the message");
        return -ENOMEM;
    }

    auto msgHdr = genlmsg_put(msg.get(), NL_AUTO_PORT, NL_AUTO_SEQ, driverID, 0,
                              flags, cmd.ncsi_cmd, 0);
    if (!msgHdr)
    {
        lg2::error("Unable to add the netlink headers , COMMAND : {COMMAND}",
                   "COMMAND", cmd.ncsi_cmd);
        return -ENOMEM;
    }

    if (package != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_PACKAGE_ID,
                          package);
        if (ret < 0)
        {
            lg2::error("Failed to set the attribute , RC : {RC} PACKAGE "
                       "{PACKAGE}",
                       "RC", ret, "PACKAGE", lg2::hex, package);
            return ret;
        }
    }

    if (channel != DEFAULT_VALUE)
    {
        ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_CHANNEL_ID,
                          channel);
        if (ret < 0)
        {
            lg2::error("Failed to set the attribute , RC : {RC} CHANNEL : "
                       "{CHANNEL}",
                       "RC", ret, "CHANNEL", lg2::hex, channel);
            return ret;
        }
    }

    ret = nla_put_u32(msg.get(), ncsi_nl_attrs::NCSI_ATTR_IFINDEX, ifindex);
    if (ret < 0)
    {
        lg2::error("Failed to set the attribute , RC : {RC} INTERFACE : "
                   "{INTERFACE}",
                   "RC", ret, "INTERFACE", lg2::hex, ifindex);
        return ret;
    }

    if (cmd.operation != DEFAULT_VALUE)
    {
        std::vector<unsigned char> pl(sizeof(NCSIPacketHeader) +
                                      cmd.payload.size());
        NCSIPacketHeader* hdr = (NCSIPacketHeader*)pl.data();

        std::copy(cmd.payload.begin(), cmd.payload.end(),
                  pl.begin() + sizeof(NCSIPacketHeader));

        hdr->type = cmd.operation;
        hdr->length = htons(cmd.payload.size());

        ret = nla_put(msg.get(), ncsi_nl_attrs::NCSI_ATTR_DATA, pl.size(),
                      pl.data());
        if (ret < 0)
        {
            lg2::error("Failed to set the data attribute, RC : {RC}", "RC",
                       ret);
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
        lg2::error("Failed to send the message , RC : {RC}", "RC", ret);
        return ret;
    }

    do
    {
        ret = nl_recvmsgs_default(socket.get());
        if (ret < 0)
        {
            lg2::error("Failed to receive the message , RC : {RC}", "RC", ret);
            break;
        }
    } while (cb_ret);

    return ret;
}

} // namespace internal

int sendOemCommand(int ifindex, int package, int channel, int operation,
                   std::span<const unsigned char> payload)
{
    lg2::debug("Send OEM Command, CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, "
               "INTERFACE_INDEX: {INTERFACE_INDEX}",
               "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
               "INTERFACE_INDEX", lg2::hex, ifindex);
    if (!payload.empty())
    {
        lg2::debug("Payload: {PAYLOAD}", "PAYLOAD", toHexStr(payload));
    }

    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, operation,
                          payload),
        package, channel, NONE, internal::sendCallBack);
}

int setChannel(int ifindex, int package, int channel)
{
    lg2::debug(
        "Set CHANNEL : {CHANNEL} , PACKAGE : {PACKAGE}, INTERFACE_INDEX: "
        "{INTERFACE_INDEX}",
        "CHANNEL", lg2::hex, channel, "PACKAGE", lg2::hex, package,
        "INTERFACE_INDEX", lg2::hex, ifindex);
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_SET_INTERFACE),
        package, channel);
}

int clearInterface(int ifindex)
{
    lg2::debug("ClearInterface , INTERFACE_INDEX : {INTERFACE_INDEX}",
               "INTERFACE_INDEX", lg2::hex, ifindex);
    return internal::applyCmd(
        ifindex, internal::Command(ncsi_nl_commands::NCSI_CMD_CLEAR_INTERFACE));
}

int getInfo(int ifindex, int package)
{
    lg2::debug(
        "Get Info , PACKAGE : {PACKAGE}, INTERFACE_INDEX: {INTERFACE_INDEX}",
        "PACKAGE", lg2::hex, package, "INTERFACE_INDEX", lg2::hex, ifindex);
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

int getCapabilities(int ifindex, int package)
{
    return internal::applyCmd(
        ifindex,
        internal::Command(ncsi_nl_commands::NCSI_CMD_SEND_CMD, NCSI_GET_CAPABILITIES),
        package, NONE, NONE, internal::sendCallBack);
}


void
printNcsiCapabilities(unsigned char *data)
{
  NCSIgetCapabilitiesResponse *pResp =
  reinterpret_cast<NCSIgetCapabilitiesResponse *>(data);

  setlocale(LC_ALL, "");
  cout<<"\nGet Capabilities response"<<endl;
  cout<<"  capabilities_flags = "<<"0x"<<hex<<ntohl(pResp->capabilitiesFlags)<<endl;
  cout<<"  broadcast_packet_filter_capabilities = "<<"0x"<<hex<<ntohl(pResp->broadcastPacketFilterCapabilities)<<endl;
  cout<<"  multicast_packet_filter_capabilities = "<<"0x"<<hex<<ntohl(pResp->multicastPacketFilterCapabilities)<<endl;
  cout<<"  buffering_capabilities = "<<"0x"<<hex<<ntohl(pResp->bufferingCapabilities)<<endl;
  cout<<"  aen_control_support = "<<"0x"<<hex<<ntohl(pResp->aenControlSupport)<<endl;
  cout<<"  unicast_filter_cnt = "<<(((pResp->filterCnt) & 0xff000000UL) >> 24)<<endl;
  cout<<"  multicast_filter_cnt = "<<(((pResp->filterCnt) & 0x00ff0000UL) >> 16)<<endl;
  cout<<"  mixed_filter_cnt = "<<(((pResp->filterCnt) & 0x0000ff00UL) >> 8)<<endl;
  cout<<"  vlan_filter_cnt = "<<(((pResp->filterCnt) & 0x000000ffUL) >> 0)<<endl;
  cout<<"  channel_cnt = "<<pResp->channelCnt<<endl;
  cout<<"  vlan_mode_support = "<<pResp->vlanModeSupport<<endl;
}


} // namespace ncsi
} // namespace network
} // namespace phosphor
