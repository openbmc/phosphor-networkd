#include "config_parser.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <regex>
#include <list>

namespace phosphor
{
namespace network
{
namespace config
{

Parser::Parser(const std::string& fileName)
{
    this->fileName = fileName;
    std::fstream stream;
    stream.open(fileName);
    parse(stream);
    stream.close();
}


const KeyValues& Parser::getSection(const std::string& section)
{
    auto it = sections.find(section);
    if (it == sections.end())
    {
        throw std::runtime_error("Unable to find the given Section");
    }
    return it->second;
}

const std::string& Parser::getValue(const std::string& section,
                                    const std::string& key)
{
    auto keyValues = getSection(section);
    auto it = keyValues.find(key);
    if (it == keyValues.end())
    {
        throw std::runtime_error("Unable to find the given key");
    }
    return it->second;
}

void Parser::setValue(const std::string& section, const std::string& key,
                      const std::string& value)
{

    sections[section][key] = value;
    writeToFile();
}

void Parser::writeToFile()
{
    std::fstream stream;
    stream.open(fileName, std::fstream::out);
    for (auto section : sections)
    {
        stream << "[" << section.first << "]\n";
        for (auto keyValue : section.second)
        {
            stream << keyValue.first << "=" << keyValue.second;
        }
    }
    stream.close();
}



void Parser::parse(std::istream& in)
{
    static const std::regex commentRegex
    {
        R"x(\s*[;#])x"
    };
    static const std::regex sectionRegex
    {
        R"x(\s*\[([^\]]+)\])x"
    };
    static const std::regex valueRegex
    {
        R"x(\s*(\S[^ \t=]*)\s*=\s*((\s?\S+)+)\s*$)x"
    };
    std::string section;
    std::smatch pieces;
    for (std::string line; std::getline(in, line);)
    {
        if (line.empty() || std::regex_match(line, pieces, commentRegex))
        {
            // skip comment lines and blank lines
        }
        else if (std::regex_match(line, pieces, sectionRegex))
        {
            if (pieces.size() == 2)
            {
                section = pieces[1].str();
            }
        }
        else if (std::regex_match(line, pieces, valueRegex))
        {
            if (pieces.size() == 4)
            {
                sections[section][pieces[1].str()] = pieces[2].str();
            }
        }
    }
}
}//namespace config
}//namespace network
}//namespace phosphor
