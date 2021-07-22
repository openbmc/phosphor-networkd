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
    MockHypSysConfig(sdbusplus::bus::bus& bus, const std::string& objPath,
                     HypNetworkMgr& parent) :
       HypSysConfig(bus, objPath, parent)
    {
    }

    void setHostName(std::string hn)
    {
        hostName(hn);
        manager.setBIOSTableAttr("vmi_hostname", hn, "String");
    }

    std::string getHostName()
    {
        return SysConfigIntf::hostName();
    }
};
} // namespace network
} // namespace phosphor
