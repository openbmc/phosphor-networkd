#include "ncsi_cmd_callback.hpp"

#include <linux/ncsi.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{ 
    static int NcsiCommandCallback::callback( struct nl_msg* msg, void* arg )
    {
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

        auto data_len = nla_len(tb[NCSI_ATTR_DATA]);
        unsigned char* data =
            (unsigned char*)nla_data(tb[NCSI_ATTR_DATA]);

        // Dump the response to stdout. Enhancement: option to save response data
        auto str = toHexStr(std::span<const unsigned char>(data, data_len));
        lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN", data_len,
                "DATA", str);

        processResponse(data);
    }
} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
