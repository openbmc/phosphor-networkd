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
    // Parse .conf file into vector of vector<string>
    static ConfigList deserialize(const std::string& filepath);

    // Write vector of vector<string> into .conf file
    static void serialize(const std::string& filepathStr, const ConfigList& config);

    static void printConfig(const ConfigList& config);

    // Parse all .conf files under a directory (like /etc/lldpd.d/)
    static std::vector<std::pair<std::string, ConfigList>>
        parseConfigDir(const std::string& dirpath);

    // Update (or insert if not found) a line that matches a specific "path"
    static void updateConfigEntry(const std::string& filepath,
                              const std::vector<std::string>& matchPath,
                              const std::vector<std::string>& newEntry);
    static ConfigList parseAllConfigs(const std::string& globalPath,
                                      const std::string& dirPath);
};

} // namespace lldp_utils
} // namespace phosphor
