#ifndef CONFIG_PARSER_HPP
#define CONFIG_PARSER_HPP

#include <string>
#include <map>
#include <unordered_map>
#include <vector>

namespace phosphor
{
namespace network
{
namespace config
{
using Section = std::string;

using KeyValues =  std::multimap<std::string, std::string>;

class Parser
{
    public:

        enum class Mode
        {
            READ,
            WRITE
        };

        Parser() = default;

        /** @brief Constructor
         *  @param[in] fileName - name of the file which will be parsed.
         */

        Parser(const std::string& fileName, Mode mode);

        /** @brief Get the value of the given key and section.
         *  @param[in] section - section name.
         *  @param[in] key - key to look for.
         *  @returns the values associated with the key.
         */

        const std::vector<std::string> getValues(const std::string& section,
                                                 const std::string& key);

        /** @brief Set the value of the given key and section.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         *  @param[in] value - value.
         */

        void setValue(const std::string& section, const std::string& key,
                      const std::string& value);

        /** @brief Remove the value associated with the given section/key.
         *         as there could be more then one value for a key.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         *  @param[in] value - value
         */

        void remove(const std::string& section, const std::string& key,
                    const std::string& value);

        /** @brief Writes all the in memory data to the file in INI format.
         */

        void writeToFile();

        /** @brief Set the file name and parse it.
         *  @param[in] fileName - name of the file.
         */

        void setFile(const std::string& fileName, Mode mode);

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

        /** @brief checks that whether the key/value exist in the
         *         given section.
         *  @param[in] section - section name.
         *  @param[in] key - key name.
         *  @param[in] value - value.
         *  @returns true if exist otherwise false.
         */

        bool isValueExist(const std::string& section, const std::string& key,
                          const std::string& value);

        //debug function
        void print();

        std::unordered_map<Section, KeyValues> sections;
        std::string fileName;
};
}//namespace config
}//namespce network
}//namespace phosphor

#endif
