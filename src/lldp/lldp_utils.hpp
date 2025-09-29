#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

namespace phosphor
{
namespace lldp_utils
{

using ConfigEntry = std::vector<std::string>;
using ConfigList  = std::vector<ConfigEntry>;

class LLDPUtils
{
  public:
    // Parse .conf files into vector of vector<string>
    static ConfigList deserialize(const std::string& filepath);

    // Write vector of vector<string> into .conf file
    static void serialize(const std::string& filepathStr, const ConfigList& config);

    static ConfigList parseAllConfigs(const std::string& globalPath,
                                      const std::string& dirPath);
};

} // namespace lldp_utils
} // namespace phosphor
