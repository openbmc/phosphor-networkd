#pragma once

#include "ncsi_util.hpp"
namespace phosphor
{
namespace network
{
namespace ncsi
{
/* @brief This function is used to retrieve the version id
 * for the package.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
int getVersionID(int ifindex, int package, int channel);
} // namespace ncsi
} // namespace network
} // namespace phosphor
