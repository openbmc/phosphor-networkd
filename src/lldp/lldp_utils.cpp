#include "lldp_utils.hpp"

#include <phosphor-logging/lg2.hpp>

namespace fs = std::filesystem;

namespace phosphor
{
namespace lldp_utils
{

ConfigList LLDPUtils::deserialize(const std::string& filepath)
{
    lg2::info("Deserializing LLDP configuration: {FILEPATH}", "FILEPATH",
              filepath);
    ConfigList config;
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        lg2::error("Failed to open config file: {FILEPATH}", "FILEPATH",
                   filepath);
        return config;
    }

    std::string line;
    while (std::getline(file, line))
    {
        if (line.empty() || line[0] == '#')
        {
            continue;
        }

        std::istringstream iss(line);
        ConfigEntry tokens;
        std::string token;
        while (iss >> token)
        {
            tokens.push_back(token);
        }

        if (!tokens.empty())
        {
            config.push_back(tokens);
        }
    }

    return config;
}

void LLDPUtils::serialize(const std::string& filepathStr,
                          const ConfigList& config)
{
    namespace fs = std::filesystem;
    fs::path filepath(filepathStr);

    lg2::info("Serializing LLDP configuration: {FILEPATH}", "FILEPATH",
              filepath.string());
    std::ofstream file(filepath, std::ios::trunc);
    if (!file.is_open())
    {
        lg2::error("Failed to open config file for writing: {FP}", "FP",
                   filepath.string());
        return;
    }

    bool isSystemConfig = (filepath.filename() == "lldpd.conf");
    std::string portName;

    if (!isSystemConfig)
    {
        portName = filepath.stem().string();
    }

    for (const auto& entry : config)
    {
        if (entry.empty())
            continue;

        bool shouldWrite = false;
        if (isSystemConfig)
        {
            shouldWrite = (entry[0] == "configure" && entry.size() > 1 &&
                           entry[1] == "system");
        }
        else if (!portName.empty())
        {
            shouldWrite = (entry[0] == "configure" && entry.size() > 2 &&
                           entry[1] == "ports" && entry[2] == portName);
        }

        if (!shouldWrite)
            continue;

        for (size_t i = 0; i < entry.size(); ++i)
        {
            file << entry[i];
            if (i + 1 < entry.size())
                file << " ";
        }
        file << "\n";
    }

    lg2::info("Finished writing LLDP config for {FILEPATH}", "FILEPATH",
              filepath.string());
}

ConfigList LLDPUtils::parseAllConfigs(const std::string& globalPath,
                                      const std::string& dirPath)
{
    ConfigList merged;

    // Parse system level config first (/etc/lldpd.conf)
    auto globalConfig = deserialize(globalPath);
    merged.insert(merged.end(), globalConfig.begin(), globalConfig.end());

    // merged now looks like this:
    // "configure" "system" "description" "BMC"
    // "configure" "system" "ip" "management" "pattern" "eth*"

    // Parse /etc/lldpd.d/*.conf next
    std::vector<fs::path> confFiles;
    for (const auto& entry : fs::directory_iterator(dirPath))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".conf")
            confFiles.push_back(entry.path());
    }

    // Sort alphabetically - lldpd behaviour
    std::sort(confFiles.begin(), confFiles.end(),
              [](const fs::path& a, const fs::path& b) {
                  return a.filename() < b.filename();
              });

    // Merge configs (similar configs in files parsed latest will
    // override earlier ones)
    for (const auto& path : confFiles)
    {
        auto config = deserialize(path);
        for (const auto& tokens : config)
        {
            // If this is a "configure ports" line, replace same port if exists
            if (tokens.size() > 2 && tokens[1] == "ports")
            {
                std::string portName = tokens[2];
                bool replaced = false;

                for (auto& entry : merged)
                {
                    if (tokens.size() == entry.size() &&
                        std::equal(tokens.begin(), tokens.end() - 2,
                                   entry.begin()))
                    {
                        // Update the entry
                        entry = tokens;
                        replaced = true;
                        break;
                    }
                }

                if (!replaced)
                    merged.push_back(tokens);
            }
            else
            {
                // system-level config
                merged.push_back(tokens);
            }
        }
    }

    return merged;
}

} // namespace lldp_utils
} // namespace phosphor
