#include "hyp_nw_config_serialize.hpp"

#include <fstream>

#include <phosphor-logging/lg2.hpp>

namespace phosphor
{
namespace network
{
namespace persistdata
{

void serialize(const NwConfigPropMap& list, std::string intf, std::string type)
{
    std::string filePath = HYP_NW_CONFIG_PERSIST_PATH + intf + "_" + type +
                           "_network";

    // Create directory if it doesnot exist
    if (!std::filesystem::exists(HYP_NW_CONFIG_PERSIST_PATH.c_str()))
    {
        lg2::info("Creating directory to store hypervisor nw config data...");
        std::filesystem::create_directory(HYP_NW_CONFIG_PERSIST_PATH.c_str());
    }

    std::ofstream serializeFile(filePath.c_str(), std::ios::out);
    if (serializeFile)
    {
        for (auto itr = list.begin(); itr != list.end(); itr++)
        {
            if (auto value = std::get_if<bool>(&itr->second))
            {
                serializeFile << itr->first << " " << *value << "\n";
            }
            else if (auto value = std::get_if<std::string>(&itr->second))
            {
                serializeFile << itr->first << " " << *value << "\n";
            }
            else if (auto value = std::get_if<int64_t>(&itr->second))
            {
                serializeFile << itr->first << " " << *value << "\n";
            }
        }
        serializeFile.close();
    }
    else
    {
        lg2::error("Couldn't open file. Exiting serialization");
    }
}

bool deserialize(NwConfigPropMap& list, std::string intf, std::string type)
{
    std::string filePath = HYP_NW_CONFIG_PERSIST_PATH + intf + "_" + type +
                           "_network";

    try
    {
        if (std::filesystem::exists(filePath))
        {
            std::ifstream deSerializeFile(filePath.c_str(), std::ifstream::in);
            std::string fileEntry;

            while (getline(deSerializeFile, fileEntry))
            {
                std::string key;
                std::string value;
                std::stringstream sStream(fileEntry);

                sStream >> key >> value;

                // Check for each key and extract the value acc to the data type
                // It should be converted to int for boolean and int64_t
                // properties
                // Bool and string types are handled here. This can be extended
                // to properties of other types.
                if (key == "Enabled")
                {
                    if (std::stoi(value))
                    {
                        list[key] = true;
                    }
                    else
                    {
                        list[key] = false;
                    }
                }
                else
                {
                    // else - for all other properties of type string
                    list[key] = value;
                }
            }
            deSerializeFile.close();
            return true;
        }
        return false;
    }
    catch (std::exception& e)
    {
        lg2::error("Failed to deserialize. Error: {ERR}", "ERR", e.what());
        std::filesystem::remove(filePath);
        return false;
    }
}

} // namespace persistdata
} // namespace network
} // namespace phosphor
