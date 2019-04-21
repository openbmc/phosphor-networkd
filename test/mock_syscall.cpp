#include "util.hpp"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <map>
#include <queue>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#define MAX_IFADDRS 5

int debugging = false;

std::map<int, std::queue<std::string>> mock_rtnetlinks;

std::map<std::string, int> mock_if_nametoindex;
std::map<int, std::string> mock_if_indextoname;
std::map<int, ether_addr> mock_macs;

void mock_clear()
{
    mock_rtnetlinks.clear();
    mock_if_nametoindex.clear();
    mock_if_indextoname.clear();
    mock_macs.clear();
}

void mock_addIF(const std::string& name, int idx,
                const std::optional<ether_addr>& mac)
{
    if (idx == 0)
    {
        throw std::invalid_argument("Bad interface index");
    }

    mock_if_nametoindex[name] = idx;
    mock_if_indextoname[idx] = name;
    if (mac)
    {
        mock_macs[idx] = *mac;
    }
}

void validateMsgHdr(const struct msghdr* msg)
{
    if (msg->msg_namelen != sizeof(sockaddr_nl))
    {
        fprintf(stderr, "bad namelen: %u\n", msg->msg_namelen);
        abort();
    }
    const auto& from = *reinterpret_cast<sockaddr_nl*>(msg->msg_name);
    if (from.nl_family != AF_NETLINK)
    {
        fprintf(stderr, "recvmsg bad family data\n");
        abort();
    }
    if (msg->msg_iovlen != 1)
    {
        fprintf(stderr, "recvmsg unsupported iov configuration\n");
        abort();
    }
}

ssize_t sendmsg_link_dump(std::queue<std::string>& msgs, std::string_view in)
{
    const ssize_t ret = in.size();
    const auto& hdrin = phosphor::copyFrom<nlmsghdr>(in);
    if (hdrin.nlmsg_type != RTM_GETLINK)
    {
        return 0;
    }

    for (const auto& [name, idx] : mock_if_nametoindex)
    {
        std::string msgBuf;
        {
            ifinfomsg info{};
            info.ifi_index = idx;
            msgBuf.append(reinterpret_cast<char*>(&info), sizeof(info));
        }
        {
            rtattr ifname{};
            ifname.rta_len = RTA_LENGTH(name.size() + 1);
            ifname.rta_type = IFLA_IFNAME;
            std::string buf(RTA_ALIGN(ifname.rta_len), '\0');
            memcpy(buf.data(), &ifname, sizeof(ifname));
            memcpy(RTA_DATA(buf.data()), name.c_str(), name.size() + 1);
            msgBuf.append(buf);
        }
        auto macIt = mock_macs.find(idx);
        if (macIt != mock_macs.end())
        {
            const auto& mac = macIt->second;
            rtattr address{};
            address.rta_len = RTA_LENGTH(sizeof(mac));
            address.rta_type = IFLA_ADDRESS;
            std::string buf(RTA_ALIGN(address.rta_len), '\0');
            memcpy(buf.data(), &address, sizeof(address));
            memcpy(RTA_DATA(buf.data()), &mac, sizeof(mac));
            msgBuf.append(buf);
        }

        nlmsghdr hdr{};
        hdr.nlmsg_len = NLMSG_LENGTH(msgBuf.size());
        hdr.nlmsg_type = RTM_NEWLINK;
        hdr.nlmsg_flags = NLM_F_MULTI;
        auto& out = msgs.emplace(hdr.nlmsg_len, '\0');
        memcpy(out.data(), &hdr, sizeof(hdr));
        memcpy(NLMSG_DATA(out.data()), msgBuf.data(), msgBuf.size());
    }

    nlmsghdr hdr{};
    hdr.nlmsg_len = NLMSG_LENGTH(0);
    hdr.nlmsg_type = NLMSG_DONE;
    hdr.nlmsg_flags = NLM_F_MULTI;
    auto& out = msgs.emplace(hdr.nlmsg_len, '\0');
    memcpy(out.data(), &hdr, sizeof(hdr));
    return ret;
}

ssize_t sendmsg_ack(std::queue<std::string>& msgs, std::string_view in)
{
    nlmsgerr ack{};
    nlmsghdr hdr{};
    hdr.nlmsg_len = NLMSG_LENGTH(sizeof(ack));
    hdr.nlmsg_type = NLMSG_ERROR;
    auto& out = msgs.emplace(hdr.nlmsg_len, '\0');
    memcpy(out.data(), &hdr, sizeof(hdr));
    memcpy(NLMSG_DATA(out.data()), &ack, sizeof(ack));
    return in.size();
}

extern "C" {

unsigned if_nametoindex(const char* ifname)
{
    auto it = mock_if_nametoindex.find(ifname);
    if (it == mock_if_nametoindex.end())
    {
        errno = ENXIO;
        return 0;
    }
    return it->second;
}

char* if_indextoname(unsigned ifindex, char* ifname)
{
    auto it = mock_if_indextoname.find(ifindex);
    if (it == mock_if_indextoname.end())
    {
        errno = ENXIO;
        return NULL;
    }
    return std::strcpy(ifname, it->second.c_str());
}

int socket(int domain, int type, int protocol)
{
    static auto real_socket =
        reinterpret_cast<decltype(&socket)>(dlsym(RTLD_NEXT, "socket"));
    int fd = real_socket(domain, type, protocol);
    if (domain == AF_NETLINK && !(type & SOCK_RAW))
    {
        fprintf(stderr, "Netlink sockets must be RAW\n");
        abort();
    }
    if (domain == AF_NETLINK && protocol == NETLINK_ROUTE)
    {
        mock_rtnetlinks[fd] = {};
    }
    return fd;
}

int close(int fd)
{
    auto it = mock_rtnetlinks.find(fd);
    if (it != mock_rtnetlinks.end())
    {
        mock_rtnetlinks.erase(it);
    }

    static auto real_close =
        reinterpret_cast<decltype(&close)>(dlsym(RTLD_NEXT, "close"));
    return real_close(fd);
}

ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    auto it = mock_rtnetlinks.find(sockfd);
    if (it == mock_rtnetlinks.end())
    {
        static auto real_sendmsg =
            reinterpret_cast<decltype(&sendmsg)>(dlsym(RTLD_NEXT, "sendmsg"));
        return real_sendmsg(sockfd, msg, flags);
    }
    auto& msgs = it->second;

    validateMsgHdr(msg);
    if (!msgs.empty())
    {
        fprintf(stderr, "Unread netlink responses\n");
        abort();
    }

    ssize_t ret;
    std::string_view iov(reinterpret_cast<char*>(msg->msg_iov[0].iov_base),
                         msg->msg_iov[0].iov_len);

    ret = sendmsg_link_dump(msgs, iov);
    if (ret != 0)
    {
        return ret;
    }

    ret = sendmsg_ack(msgs, iov);
    if (ret != 0)
    {
        return ret;
    }

    errno = ENOSYS;
    return -1;
}

ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    auto it = mock_rtnetlinks.find(sockfd);
    if (it == mock_rtnetlinks.end())
    {
        static auto real_recvmsg =
            reinterpret_cast<decltype(&recvmsg)>(dlsym(RTLD_NEXT, "recvmsg"));
        return real_recvmsg(sockfd, msg, flags);
    }
    auto& msgs = it->second;

    validateMsgHdr(msg);
    constexpr size_t required_buf_size = 8192;
    if (msg->msg_iov[0].iov_len < required_buf_size)
    {
        fprintf(stderr, "recvmsg iov too short: %zu\n",
                msg->msg_iov[0].iov_len);
        abort();
    }
    if (msgs.empty())
    {
        fprintf(stderr, "No pending netlink responses\n");
        abort();
    }

    ssize_t ret = 0;
    auto data = reinterpret_cast<char*>(msg->msg_iov[0].iov_base);
    while (!msgs.empty())
    {
        const auto& msg = msgs.front();
        if (NLMSG_ALIGN(ret) + msg.size() > required_buf_size)
        {
            break;
        }
        ret = NLMSG_ALIGN(ret);
        memcpy(data + ret, msg.data(), msg.size());
        ret += msg.size();
        msgs.pop();
    }
    return ret;
}

} // extern "C"
