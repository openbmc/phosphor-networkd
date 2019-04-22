#include <arpa/inet.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstdarg>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>

#define MAX_IFADDRS 5

int debugging = false;

/* Data for mocking getifaddrs */
struct ifaddr_storage
{
    struct ifaddrs ifaddr;
    struct sockaddr_storage addr;
    struct sockaddr_storage mask;
    struct sockaddr_storage bcast;
} mock_ifaddr_storage[MAX_IFADDRS];

struct ifaddrs* mock_ifaddrs = nullptr;

int ifaddr_count = 0;

/* Stub library functions */
void freeifaddrs(ifaddrs* ifp)
{
    return;
}

std::map<std::string, int> mock_if_nametoindex;
std::map<int, std::string> mock_if_indextoname;
std::map<std::string, ether_addr> mock_macs;

void mock_addIF(const std::string& name, int idx, const ether_addr& mac)
{
    if (idx == 0)
    {
        throw std::invalid_argument("Bad interface index");
    }

    mock_if_nametoindex[name] = idx;
    mock_if_indextoname[idx] = name;
    mock_macs[name] = mac;
}

void mock_addIP(const char* name, const char* addr, const char* mask,
                unsigned int flags)
{
    struct ifaddrs* ifaddr = &mock_ifaddr_storage[ifaddr_count].ifaddr;

    struct sockaddr_in* in =
        reinterpret_cast<sockaddr_in*>(&mock_ifaddr_storage[ifaddr_count].addr);
    struct sockaddr_in* mask_in =
        reinterpret_cast<sockaddr_in*>(&mock_ifaddr_storage[ifaddr_count].mask);

    in->sin_family = AF_INET;
    in->sin_port = 0;
    in->sin_addr.s_addr = inet_addr(addr);

    mask_in->sin_family = AF_INET;
    mask_in->sin_port = 0;
    mask_in->sin_addr.s_addr = inet_addr(mask);

    ifaddr->ifa_next = nullptr;
    ifaddr->ifa_name = const_cast<char*>(name);
    ifaddr->ifa_flags = flags;
    ifaddr->ifa_addr = reinterpret_cast<struct sockaddr*>(in);
    ifaddr->ifa_netmask = reinterpret_cast<struct sockaddr*>(mask_in);
    ifaddr->ifa_data = nullptr;

    if (ifaddr_count > 0)
        mock_ifaddr_storage[ifaddr_count - 1].ifaddr.ifa_next = ifaddr;
    ifaddr_count++;
    mock_ifaddrs = &mock_ifaddr_storage[0].ifaddr;
}

extern "C" {

int getifaddrs(ifaddrs** ifap)
{
    *ifap = mock_ifaddrs;
    if (mock_ifaddrs == nullptr)
        return -1;
    return (0);
}

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
    if (ifindex == 0)
    {
        errno = ENXIO;
        return NULL;
    }
    auto it = mock_if_indextoname.find(ifindex);
    if (it == mock_if_indextoname.end())
    {
        // TODO: Return ENXIO once other code is mocked out
        return std::strcpy(ifname, "invalid");
    }
    return std::strcpy(ifname, it->second.c_str());
}

int ioctl(int fd, unsigned long int request, ...)
{
    va_list vl;
    va_start(vl, request);
    void* data = va_arg(vl, void*);
    va_end(vl);

    if (request == SIOCGIFHWADDR)
    {
        auto req = reinterpret_cast<ifreq*>(data);
        auto it = mock_macs.find(req->ifr_name);
        if (it == mock_macs.end())
        {
            errno = ENXIO;
            return -1;
        }
        std::memcpy(req->ifr_hwaddr.sa_data, &it->second, sizeof(it->second));
        return 0;
    }

    static auto real_ioctl =
        reinterpret_cast<decltype(&ioctl)>(dlsym(RTLD_NEXT, "ioctl"));
    return real_ioctl(fd, request, data);
}

} // extern "C"
