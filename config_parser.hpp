#pragma once

#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <experimental/filesystem>

namespace phosphor
{
namespace network
{
namespace config
{

using Section = std::string;
using KeyValues =  std::multimap<std::string, std::string>;
namespace fs = std::experimental::filesystem;

class Parser
{
    public:

        Parser() = default;

        /** @brief Constructor
         *  @param[in] fileName - Absolute path of the file which will be parsed.
         */

        Parser(const fs::path& fileName);

        /** @brief Get the values of the given key and section.
         *  @param[in] section - section name.
         *  @param[in] key - key to look for.
         *  @returns the values associated with the key.
         */

        std::vector<std::string> getValues(const std::string& section,
                                           const std::string& key);

        /** @brief Set the value of the given key and section.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         *  @param[in] value - value.
         */

        void setValue(const std::string& section, const std::string& key,
                      const std::string& value);


        /** @brief Set the file name and parse it.
         *  @param[in] fileName - Absolute path of the file.
         */

        void setFile(const fs::path& fileName);

    private:

        /** @brief Parses the given file and fills the data.
         *  @param[in] stream - inputstream.
         */

        void parse(std::istream& stream);

        /** @brief Get all the key values of the given section.
         *  @param[in] section - section name.
         *  @returns the map of the key and value.
         */

        KeyValues getSection(const std::string& section);

        /** @brief checks that whether the value exist in the
         *         given section.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         *  @param[in] value - value.
         *  @returns true if exist otherwise false.
         */

        bool isValueExist(const std::string& section, const std::string& key,
                          const std::string& value);

        std::unordered_map<Section, KeyValues> sections;
        fs::path filePath;
};

}//namespace config
}//namespce network
}//namespace phosphor
