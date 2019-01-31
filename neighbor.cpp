#include "config.h"

#include "neighbor.hpp"

#include "ethernet_interface.hpp"
#include "util.hpp"

#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>
#include <stdexcept>
#include <string_view>
#include <system_error>

namespace phosphor
{
namespace network
{

NeighborInfo parseNeighbor(std::string_view msg)
{
    struct ndmsg ndm;
    if (msg.size() < sizeof(ndm))
    {
        throw std::runtime_error("Bad neighbor msg");
    }
    memcpy(&ndm, msg.data(), sizeof(ndm));
    auto attrs = msg.substr(sizeof(ndm));

    NeighborInfo info;
    info.permanent = ndm.ndm_state & NUD_PERMANENT;
    bool set_addr = false;
    while (!attrs.empty())
    {
        struct rtattr hdr;
        if (attrs.size() < sizeof(hdr))
        {
            throw std::runtime_error("Bad rtattr header");
        }
        memcpy(&hdr, attrs.data(), sizeof(hdr));
        if (hdr.rta_len < sizeof(hdr))
        {
            throw std::runtime_error("Invalid rtattr length");
        }
        if (attrs.size() < hdr.rta_len)
        {
            throw std::runtime_error("Not enough data for rtattr");
        }
        auto data = attrs.substr(RTA_LENGTH(0), hdr.rta_len - RTA_LENGTH(0));
        if (hdr.rta_type == NDA_LLADDR)
        {
            info.mac.emplace();
            if (data.size() != info.mac->size())
            {
                throw std::runtime_error("Invalid LLADDR size");
            }
            memcpy(info.mac->data(), data.data(), info.mac->size());
        }
        else if (hdr.rta_type == NDA_DST)
        {
            if (ndm.ndm_family == AF_INET)
            {
                if (data.size() != sizeof(struct in_addr))
                {
                    throw std::runtime_error("Invalid ADDR4 size");
                }
                auto& ref = info.address.emplace<struct in_addr>();
                memcpy(&ref, data.data(), sizeof(ref));
            }
            else if (ndm.ndm_family == AF_INET6)
            {
                if (data.size() != sizeof(struct in6_addr))
                {
                    throw std::runtime_error("Invalid ADDR6 size");
                }
                auto& ref = info.address.emplace<struct in6_addr>();
                memcpy(&ref, data.data(), sizeof(ref));
            }
            else
            {
                throw std::runtime_error("Unsupported family");
            }
            set_addr = true;
        }
        attrs.remove_prefix(RTA_ALIGN(hdr.rta_len));
    }
    if (!set_addr)
    {
        throw std::runtime_error("Missing address");
    }
    return info;
}

bool parseNeighborMsgs(std::string_view msgs, std::vector<NeighborInfo>& info)
{
    while (!msgs.empty())
    {
        struct nlmsghdr hdr;
        if (msgs.size() < sizeof(hdr))
        {
            throw std::runtime_error("Bad neighbor netlink header");
        }
        memcpy(&hdr, msgs.data(), sizeof(hdr));
        if (hdr.nlmsg_type == NLMSG_DONE)
        {
            if (msgs.size() > hdr.nlmsg_len)
            {
                throw std::runtime_error("Unexpected extra netlink messages");
            }
            return true;
        }
        else if (hdr.nlmsg_type != RTM_NEWNEIGH)
        {
            throw std::runtime_error("Bad neighbor msg type");
        }
        if (hdr.nlmsg_len < sizeof(hdr))
        {
            throw std::runtime_error("Invalid nlmsg length");
        }
        if (msgs.size() < hdr.nlmsg_len)
        {
            throw std::runtime_error("Bad neighbor payload");
        }
        auto msg = msgs.substr(NLMSG_HDRLEN, hdr.nlmsg_len - NLMSG_HDRLEN);
        msgs.remove_prefix(NLMSG_ALIGN(hdr.nlmsg_len));
        info.push_back(parseNeighbor(msg));
    }

    return false;
}

std::vector<NeighborInfo> receiveNeighbors(int sock)
{
    // We need to make sure we have enough room for an entire packet otherwise
    // it gets truncated. The netlink docs guarantee packets will not exceed 8K
    char buf[8192];

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    struct sockaddr_nl from;
    memset(&from, 0, sizeof(from));
    from.nl_family = AF_NETLINK;

    struct msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_name = &from;
    hdr.msg_namelen = sizeof(from);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    std::vector<NeighborInfo> info;
    while (true)
    {
        ssize_t recvd = recvmsg(sock, &hdr, 0);
        if (recvd <= 0)
        {
            throw std::system_error(errno, std::generic_category(),
                                    "recvmsg neighbor");
        }
        if (parseNeighborMsgs(std::string_view(buf, recvd), info))
        {
            return info;
        }
    }
}

void requestNeighbors(int sock)
{
    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;

    struct
    {
        struct nlmsghdr hdr;
        struct ndmsg msg;
    } data;
    memset(&data, 0, sizeof(data));
    data.hdr.nlmsg_len = sizeof(data);
    data.hdr.nlmsg_type = RTM_GETNEIGH;
    data.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    data.msg.ndm_family = AF_UNSPEC;

    struct iovec iov;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = &data;
    iov.iov_len = sizeof(data);

    struct msghdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_name = reinterpret_cast<struct sockaddr*>(&dst);
    hdr.msg_namelen = sizeof(dst);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    if (sendmsg(sock, &hdr, 0) < 0)
    {
        throw std::system_error(errno, std::generic_category(),
                                "sendmsg neighbor dump");
    }
}

int getNetlink(int protocol)
{
    int sock = socket(AF_NETLINK, SOCK_DGRAM, protocol);
    if (sock < 0)
    {
        throw std::system_error(errno, std::generic_category(), "netlink open");
    }

    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    int r =
        bind(sock, reinterpret_cast<struct sockaddr*>(&local), sizeof(local));
    if (r < 0)
    {
        close(sock);
        throw std::system_error(errno, std::generic_category(), "netlink bind");
    }
    return sock;
}

std::vector<NeighborInfo> getCurrentNeighbors()
{
    Descriptor netlink(getNetlink(NETLINK_ROUTE));
    requestNeighbors(netlink());
    return receiveNeighbors(netlink());
}

Neighbor::Neighbor(sdbusplus::bus::bus& bus, const char* objPath,
                   EthernetInterface& parent, const std::string& ipAddress,
                   const std::string& macAddress, State state) :
    NeighborObj(bus, objPath, true),
    parent(parent)
{
    this->iPAddress(ipAddress);
    this->mACAddress(macAddress);
    this->state(state);

    // Emit deferred signal.
    emit_object_added();
}

void Neighbor::delete_()
{
    parent.deleteStaticNeighborObject(iPAddress());
}

} // namespace network
} // namespace phosphor
