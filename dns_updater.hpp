#pragma once

#include <map>

#include "watch.hpp"

namespace phosphor
{
namespace network
{
namespace dns
{
namespace updater
{

/** @brief Implementation of core watch call back
  * @param [in] fileInfo - map of file info  path:event
  */
void readNetIfState(const std::string& netIffile);

} // namespace updater
} // namepsace dns
} // namespace network
} // namespace phosphor

