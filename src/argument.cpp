/**
 * Copyright © 2018 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "argument.hpp"

#include <algorithm>
#include <iostream>
#include <iterator>

namespace phosphor
{
namespace network
{
namespace ncsi
{

ArgumentParser::ArgumentParser(int argc, char** argv)
{
    int option = 0;
    while (-1 != (option = getopt_long(argc, argv, optionStr, options, NULL)))
    {
        if ((option == '?') || (option == 'h'))
        {
            usage(argv);
            exit(-1);
        }

        auto i = &options[0];
        while ((i->val != option) && (i->val != 0))
        {
            ++i;
        }

        if (i->val)
        {
            arguments[i->name] = (i->has_arg ? optarg : trueString);
        }
    }
}

const std::string& ArgumentParser::operator[](const std::string& opt)
{
    auto i = arguments.find(opt);
    if (i == arguments.end())
    {
        return emptyString;
    }
    else
    {
        return i->second;
    }
}

void ArgumentParser::usage(char** argv)
{
    std::cerr << "Usage: " << argv[0] << " [options]\n";
    std::cerr << "Options:\n";
    // clang-format off
    std::cerr << "    --help | -h       Print this menu.\n";
    std::cerr << "    --index=<device index> | -x <device index> Specify device ifindex.\n";
    std::cerr << "    --package=<package> | -p <package> Specify a package.\n";
    std::cerr << "    --channel=<channel> | -c <channel> Specify a channel.\n";
    std::cerr << "    --info  | -i      Retrieve info about NCSI topology.\n";
    std::cerr << "    --set   | -s      Set a specific package/channel.\n";
    std::cerr << "    --clear | -r      Clear all the settings on the interface.\n";
    std::cerr << "    --oem-payload=<hex data...> | -o <hex data...> Send an OEM command with payload.\n";
    std::cerr << "\n";
    std::cerr << "Example commands:\n";
    std::cerr << "    1) Retrieve topology information:\n";
    std::cerr << "         ncsi-netlink -x 3 -p 0 -i\n";
    std::cerr << "    2) Set preferred package\n";
    std::cerr << "         ncsi-netlink -x 3 -p 0 -s\n";
    std::cerr << "    3) Set preferred channel\n";
    std::cerr << "         ncsi-netlink -x 3 -p 0 -c 1 -s\n";
    std::cerr << "    4) Clear preferred channel\n";
    std::cerr << "         ncsi-netlink -x 3 -p 0 -r\n";
    std::cerr << "    5) Send NCSI Command\n";
    std::cerr << "         ncsi-netlink -x 3 -p 0 -c 0 -o 50000001572100\n";
    std::cerr << "\n";
    // clang-format on
    std::cerr << std::flush;
}

const option ArgumentParser::options[] = {
    {"info", no_argument, NULL, 'i'},
    {"set", no_argument, NULL, 's'},
    {"clear", no_argument, NULL, 'r'},
    {"oem-payload", required_argument, NULL, 'o'},
    {"package", required_argument, NULL, 'p'},
    {"channel", required_argument, NULL, 'c'},
    {"index", required_argument, NULL, 'x'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0},
};

const char* ArgumentParser::optionStr = "irsx:o:p:c:h?";

const std::string ArgumentParser::trueString = "true";
const std::string ArgumentParser::emptyString = "";

} // namespace ncsi
} // namespace network
} // namespace phosphor
