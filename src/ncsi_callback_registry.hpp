#pragma once

#include <map>
#include <memory>

#include "ncsi_cmd_callback.hpp"
#include "ncsi_oem_cmd_callback.hpp"
#include "ncsi_disable_vlan_callback.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{ 
    using CallBack = int (*)(struct nl_msg* msg, void* arg);

    constexpr int NcsiSendOemCommand = 0x50;
    constexpr int NcsiDisableVlan = 0x0D;

    class NcsiCallbackRegistry
    {
      public:

        static NcsiCallbackRegistry& getInstance()
        {
            static NcsiCallbackRegistry instance;
            return instance;
        }

        CallBack getCallback(int operation)
        {
            auto callback = callbacks_[operation].get();
            return callback ? callback->callback : nullptr;
        }

        std::unique_ptr<NcsiCommandCallback>& operator[](int cmd)
        {
            return callbacks_[cmd];
        }

      private:

        NcsiCallbackRegistry()
        {
            callbacks_[NcsiSendOemCommand]
             = std::make_unique<SendOemCommandCallback>();
            callbacks_[NcsiDisableVlan]
             = std::make_unique<DisableVlanCallback>();
        }

        std::map<int, std::unique_ptr<NcsiCommandCallback>> callbacks_;
    };

} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
