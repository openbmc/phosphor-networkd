#include "lldp_utils.hpp"

#include <phosphor-logging/lg2.hpp>

namespace fs = std::filesystem;

namespace phosphor
{
namespace lldp_utils
{

ConfigList LLDPUtils::deserialize(const std::string& filepath)
{
    lg2::info("**** Inside deserialize. FilePath: {FP}", "FP", filepath);
    ConfigList config;
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        lg2::error("Failed to open config file: {FILEPATH}", "FILEPATH", filepath);
        return config;
    }

    std::string line;
    while (std::getline(file, line))
    {
        lg2::error("**** Inside getline");
        if (line.empty() || line[0] == '#')
        {
            lg2::error("**** Inside line empty or starts with #");
            continue;
        }

        std::istringstream iss(line);
        ConfigEntry tokens;
        std::string token;
        while (iss >> token)
        {
            lg2::error("**** Inside while. Token: {TOKEN}", "TOKEN", token);
            tokens.push_back(token);
        }

        if (!tokens.empty())
        {
            lg2::error("**** Inside !tokens.empty, push to config");
            config.push_back(tokens);
        }
    }

    return config;
}

void LLDPUtils::serialize(const std::string& filepathStr, const ConfigList& config)
{
    namespace fs = std::filesystem;
    fs::path filepath(filepathStr);

    lg2::info("Serializing LLDP configuration: {FILEPATH}", "FILEPATH", filepath.string());
    std::ofstream file(filepath, std::ios::trunc);
    if (!file.is_open())
    {
        lg2::error("Failed to open config file for writing: {FP}", "FP", filepath.string());
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
            lg2::error("**** Inside system config");
            shouldWrite = (entry[0] == "configure" && entry.size() > 1 &&
                           entry[1] == "system");
        }
        else if (!portName.empty())
        {
            lg2::error("**** Inside portname - port config");
            shouldWrite = (entry[0] == "configure" && entry.size() > 2 &&
                           entry[1] == "ports" && entry[2] == portName);
        }

        if (!shouldWrite)
            continue;

        for (size_t i = 0; i < entry.size(); ++i)
        {
            lg2::error("**** Inside for loop, entry[i]: {ENTRY}", "ENTRY", entry[i]);
            file << entry[i];
            if (i + 1 < entry.size())
                file << " ";
        }
        file << "\n";
    }

    lg2::info("Finished writing LLDP config for {FILEPATH}", "FILEPATH", filepath.string());
}

void LLDPUtils::printConfig(const ConfigList& config)
{
    for (const auto& entry : config)
    {
        for (const auto& token : entry)
        {
            lg2::error("Token: {TOKEN}", "TOKEN", token);
        }
    }
}

std::vector<std::pair<std::string, ConfigList>>
LLDPUtils::parseConfigDir(const std::string& dirpath)
{
    std::vector<std::pair<std::string, ConfigList>> allConfigs;

    if (!fs::exists(dirpath))
    {
        lg2::error("Directory not found: {DIRPATH}", "DIRPATH", dirpath);
        return allConfigs;
    }

    std::vector<fs::path> confFiles;

    // Collect all .conf files
    for (const auto& entry : fs::directory_iterator(dirpath))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".conf")
        {
            confFiles.push_back(entry.path());
        }
    }

    // Sort alphabetically by filename
    std::sort(confFiles.begin(), confFiles.end(),
              [](const fs::path& file1, const fs::path& file2) {
                  return file1.filename() < file2.filename();
              });

    // Now deserialize in sorted order
    for (const auto& path : confFiles)
    {
        lg2::debug("Parsing config file: {FILE}", "FILE", path.filename());
        auto config = deserialize(path);
        allConfigs.emplace_back(path.filename(), config);
    }

    return allConfigs;
}

void LLDPUtils::updateConfigEntry(const std::string& filepath,
                                  const std::vector<std::string>& matchPath,
                                  const std::vector<std::string>& newEntry)
{
    lg2::error("**** Inside Update config entry. FilePath: {FP}", "FP", filepath); // MatchPath: {MP}, NewEntry: {NE}", "MP", matchPath, "NE", newEntry);
    // 1. Read existing config
    auto config = deserialize(filepath);
    bool updated = false;

    // 2. Try to find a matching entry by prefix
    for (auto& entry : config)
    {
        bool match = true;
        if (entry.size() < matchPath.size())
        {
            lg2::error("**** entry size < matchpath size");
            match = false;
        }
        else
        {
            lg2::error("**** Inside else");
            for (size_t i = 0; i < matchPath.size(); ++i)
            {
                lg2::error("**** entry[i]: {EI} and mp[i]: {MPI}", "EI", entry[i], "MPI", matchPath[i]);
                if (entry[i] != matchPath[i])
                {
                    match = false;
                    break;
                }
            }
        }

        // Replace matching line with new entry
        if (match)
        {
            lg2::error("**** Inside match true");
            entry = newEntry;
            updated = true;
            break;
        }
    }

    // 3. If not found, append as a new line
    if (!updated)
    {
        lg2::error("**** Inside !updated, so appending as a new line");
        config.push_back(newEntry);
    }

    lg2::error("**** Calling serialize");
    // 4. Write back to file
    serialize(filepath, config);
}

ConfigList LLDPUtils::parseAllConfigs(const std::string& globalPath,
                                      const std::string& dirPath)
{
    lg2::info("**** Inside parseAllConfigs. Global path: {GP}, dirPath: {DP}", "GP", globalPath, "DP", dirPath);
    ConfigList merged;

    // Parse /etc/lldpd.conf first
    lg2::info("**** Calling deserialise of the globalPath");
    auto globalConfig = deserialize(globalPath);
    merged.insert(merged.end(), globalConfig.begin(), globalConfig.end());

    // merged now looks like this:
    // "configure" "system" "description" "BMC"
    // "configure" "system" "ip" "management" "pattern" "eth*"

    // Parse /etc/lldpd.d/*.conf next
    lg2::info("**** Parsing through the dirPath");
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

    // Merge configs (later files override earlier ones)
    for (const auto& path : confFiles)
    {
        lg2::error("**** Inside confFiles iterator. Path: {PATH}", "PATH", path);
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
                    if (tokens.size() == entry.size() && std::equal(tokens.begin(), tokens.end() - 2, entry.begin()))
                    {
                        // Update the entry
                            lg2::error("**** Updating entry");
                        entry = tokens;
                        replaced = true;
                        break;
                    }

                    /*if (entry.size() > 2 && entry[1] == "ports" && entry[2] == portName)
                    {
                        entry = tokens;
                        replaced = true;
                        break;
                    }*/
                }

                if (!replaced)
                    merged.push_back(tokens);
            }
            else
            {
                // System-level config, just add
                merged.push_back(tokens);
            }
        }
    }

    return merged;
}

} // namespace lldp_utils
} // namespace phosphor
