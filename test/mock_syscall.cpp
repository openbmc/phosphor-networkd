#include "mock_syscall.hpp"

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

#include <stdplus/raw.hpp>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <map>
#include <queue>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

std::map<int, std::queue<std::string>> mock_rtnetlinks;

using phosphor::network::InterfaceInfo;

std::map<std::string, InterfaceInfo> mock_if;

void phosphor::network::system::mock_clear()
{
    mock_rtnetlinks.clear();
    mock_if.clear();
}

void phosphor::network::system::mock_addIF(const InterfaceInfo& info)
{
    if (info.idx == 0)
    {
        throw std::invalid_argument("Bad interface index");
    }
    for (const auto& [_, iinfo] : mock_if)
    {
        if (iinfo.idx == info.idx || iinfo.name == info.name)
        {
            throw std::invalid_argument("Interface already exists");
        }
    }
    mock_if.emplace(info.name.value(), info);
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

void appendRTAttr(std::string& msgBuf, unsigned short type,
                  std::string_view data)
{
    const auto rta_begin = msgBuf.size();
    msgBuf.append(RTA_SPACE(data.size()), '\0');
    auto& rta = *reinterpret_cast<rtattr*>(msgBuf.data() + rta_begin);
    rta.rta_len = RTA_LENGTH(data.size());
    rta.rta_type = type;
    std::copy(data.begin(), data.end(),
              msgBuf.data() + rta_begin + RTA_LENGTH(0));
}

ssize_t sendmsg_link_dump(std::queue<std::string>& msgs, std::string_view in)
{
    if (const auto& hdrin = *reinterpret_cast<const nlmsghdr*>(in.data());
        hdrin.nlmsg_type != RTM_GETLINK)
    {
        return 0;
    }

    std::string msgBuf;
    msgBuf.reserve(8192);
    for (const auto& [name, i] : mock_if)
    {
        if (msgBuf.size() > 4096)
        {
            msgs.emplace(std::move(msgBuf));
        }
        const auto nlbegin = msgBuf.size();
        msgBuf.append(NLMSG_SPACE(sizeof(ifinfomsg)), '\0');
        {
            auto& info = *reinterpret_cast<ifinfomsg*>(
                msgBuf.data() + nlbegin + NLMSG_HDRLEN);
            info.ifi_index = i.idx;
            info.ifi_flags = i.flags;
        }
        if (i.name)
        {
            appendRTAttr(msgBuf, IFLA_IFNAME, {name.data(), name.size() + 1});
        }
        if (i.mac)
        {
            appendRTAttr(msgBuf, IFLA_ADDRESS,
                         stdplus::raw::asView<char>(*i.mac));
        }
        if (i.mtu)
        {
            appendRTAttr(msgBuf, IFLA_MTU, stdplus::raw::asView<char>(*i.mtu));
        }
        auto& hdr = *reinterpret_cast<nlmsghdr*>(msgBuf.data() + nlbegin);
        hdr.nlmsg_len = msgBuf.size() - nlbegin;
        hdr.nlmsg_type = RTM_NEWLINK;
        hdr.nlmsg_flags = NLM_F_MULTI;
        msgBuf.resize(NLMSG_ALIGN(msgBuf.size()), '\0');
    }
    const auto nlbegin = msgBuf.size();
    msgBuf.append(NLMSG_SPACE(0), '\0');
    auto& hdr = *reinterpret_cast<nlmsghdr*>(msgBuf.data() + nlbegin);
    hdr.nlmsg_len = NLMSG_LENGTH(0);
    hdr.nlmsg_type = NLMSG_DONE;
    hdr.nlmsg_flags = NLM_F_MULTI;

    msgs.emplace(std::move(msgBuf));
    return in.size();
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

extern "C"
{
int ioctl(int fd, unsigned long int request, ...)
{
    va_list vl;
    va_start(vl, request);
    void* data = va_arg(vl, void*);
    va_end(vl);

    auto req = reinterpret_cast<ifreq*>(data);
    if (request == SIOCGIFFLAGS)
    {
        auto it = mock_if.find(req->ifr_name);
        if (it == mock_if.end())
        {
            errno = ENXIO;
            return -1;
        }
        req->ifr_flags = it->second.flags;
        return 0;
    }
    else if (request == SIOCGIFMTU)
    {
        auto it = mock_if.find(req->ifr_name);
        if (it == mock_if.end())
        {
            errno = ENXIO;
            return -1;
        }
        if (!it->second.mtu)
        {
            errno = EOPNOTSUPP;
            return -1;
        }
        req->ifr_mtu = *it->second.mtu;
        return 0;
    }

    static auto real_ioctl =
        reinterpret_cast<decltype(&ioctl)>(dlsym(RTLD_NEXT, "ioctl"));
    return real_ioctl(fd, request, data);
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
