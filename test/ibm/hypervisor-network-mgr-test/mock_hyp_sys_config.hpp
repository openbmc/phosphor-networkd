#pragma once

#include "config.h"

#include "hyp_sys_config.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

class MockHypSysConfig : public phosphor::network::HypSysConfig
{
  public:
    MockHypSysConfig(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                     sdbusplus::message::object_path objPath,
                     stdplus::PinnedRef<HypNetworkMgr> parent) :
        HypSysConfig(bus, objPath, parent)
    {}

    void setHostname(std::string hn)
    {
        SysConfigIntf::hostName(hn);
        manager.get().setBIOSTableAttr("vmi_hostname", hn, "String");
    }

    const std::string getHostname()
    {
        return SysConfigIntf::hostName();
    }
};
} // namespace network
} // namespace phosphor
