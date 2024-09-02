#pragma once

#include <map>
#include <memory>

#include "ncsi_cmd_callback.hpp"
#include "ncsi_oem_command_callback.hpp"
#include "ncsi_disable_vlan_callback.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{ 
    enum class NcsiCommand
    {
        SEND_OEM_COMMAND = 0x50,
        DISABLE_VLAN = 0x0D,
    };

    class NcsiCallbackRegistry
    {
      public:

        static NcsiCallbackRegistry& getInstance()
        {
            static NcsiCallbackRegistry instance;
            return instance;
        }

        std::map<NcsiCommand, std::unique_ptr<NcsiCommandCallback>>&
                                                                 getCallbacks()
        {
            return callbacks_;
        }

      private:

        NcsiCallbackRegistry()
        {
            callbacks_[NcsiCommand::SEND_OEM_COMMAND]
             = std::make_unique<SendOemCommandCallback>();
            callbacks_[NcsiCommand::DISABLE_VLAN]
             = std::make_unique<DisableVlanCallback>();
        }

        std::map<NcsiCommand, std::unique_ptr<NcsiCommandCallback>> callbacks_;
    };

} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
