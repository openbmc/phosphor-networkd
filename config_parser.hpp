#ifndef CONFIG_PARSER_HPP
#define CONFIG_PARSER_HPP

#include <string>
#include <unordered_map>
#include <list>

namespace phosphor
{
namespace network
{
namespace config
{
using Section = std::string;
using KeyValues =  std::unordered_map<std::string, std::string>;

class Parser
{
    public:

        Parser() = default;

        /** @brief Constructor
         *  @param[in] fileName - name of the file which will be parsed.
         */

        Parser(const std::string& fileName);

        /** @brief Get the value of the given key and section.
         *  @param[in] section - section name.
         *  @param[in] key - key to look for.
         *  @returns the value associated with the key.
         */

        const std::string& getValue(const std::string& section,
                                    const std::string& key);

        /** @brief Set the value of the given key and section.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         *  @param[in] value - value.
         */

        void setValue(const std::string& section, const std::string& key,
                      const std::string& value);

        /** @brief Remove the key from the given section.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         */

        void removeKey(const std::string& section, const std::string& key);

        /** @brief Writes all the in memory data to the file in INI format.
         */

        void writeToFile();

        /** @brief Set the file name and parse it.
         *  @param[in] fileName - name of the file.
         */

        void setFile(const std::string& fileName);

    private:

        /** @brief Parses the given file and fills the data.
         *  @param[in] stream - inputstream.
         */

        void parse(std::istream& stream);

        /** @brief Get all the key values of the given section.
         *  @param[in] section - section name.
         *  @returns the map of the key and value.
         */

        KeyValues& getSection(const std::string& section);

        //debug function
        void printMap();

        std::unordered_map<Section, KeyValues> sections;
        std::string fileName;
};
}//namespace config
}//namespce network
}//namespace phosphor

#endif
