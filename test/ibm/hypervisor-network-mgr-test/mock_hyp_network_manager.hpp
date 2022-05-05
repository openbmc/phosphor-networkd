#pragma once

#include "config.h"

#include "hyp_network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

class MockHypManager : public phosphor::network::HypNetworkMgr
{
  public:
    MockHypManager(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                   const char* path) :
        phosphor::network::HypNetworkMgr(bus, event, path)
    {
    }

    void setDefaultBIOSTableAttrs()
    {
        biosTableAttrs.clear();
        setIf0DefaultBIOSTableAttrs();
        setIf1DefaultBIOSTableAttrs();
        setDefaultHostnameInBIOSTableAttrs();
    }

    void setBIOSAttribute(std::string attrName,
                          std::variant<std::string, int64_t> attrValue,
                          std::string attrType)
    {
        auto findAttr = biosTableAttrs.find(attrName);
        if (findAttr != biosTableAttrs.end())
        {
            if (attrType == "Integer")
            {
                int64_t value = std::get<int64_t>(attrValue);
                if (value != std::get<int64_t>(findAttr->second))
                {
                    biosTableAttrs.erase(findAttr);
                    biosTableAttrs.emplace(attrName, value);
                }
            }
            else if (attrType == "String")
            {
                std::string value = std::get<std::string>(attrValue);
                if (value != std::get<std::string>(findAttr->second))
                {
                    biosTableAttrs.erase(findAttr);
                    biosTableAttrs.emplace(attrName, value);
                }
            }
        }
    }

    friend class TestHypNetworkManager;
};

} // namespace network
} // namespace phosphor
