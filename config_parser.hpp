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
        Parser(const std::string& fileName);

        const KeyValues& getSection(const std::string& section);

        const std::string& getValue(const std::string& section, const std::string& key);
        void setValue(const std::string& section, const std::string& key,
                      const std::string& value);

    private:
        void parse(std::istream& filename);
        void writeToFile();

        std::unordered_map<Section, KeyValues> sections;
        std::string fileName;
};
}//namespace config
}//namespce network
}//namespace phosphor

#endif
