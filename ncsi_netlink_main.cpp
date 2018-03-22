/**
 * Copyright © 2016 IBM Corporation
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
#include "ncsi_util.hpp"

#include <iostream>
#include <string>

static void exitWithError(const char* err, char** argv)
{
    phosphor::network::ArgumentParser::usage(argv);
    std::cerr << "ERROR: " << err << "\n";
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    using namespace phosphor::network;
    // Read arguments.
    auto options = ArgumentParser(argc, argv);

    // Parse out package argument.
    auto package = (options)["package"];
    auto packageInt = atoi(package.c_str());
    if (packageInt < 0)
    {
        exitWithError("Package not specified.", argv);
    }

    // Parse out channel argument.
    auto channel = (options)["channel"];
    auto channelInt = atoi(channel.c_str());
    if (channelInt < 0 )
    {
        exitWithError("Channel not specified.", argv);
    }

    auto intfIndex = (options)["index"];
    auto indexInt = atoi(intfIndex.c_str());
    if (indexInt < 0 )
    {
        exitWithError("Interface index not specified.", argv);
    }

    auto setCmd = (options)["set"];
    if(setCmd == "true")
    {
        ncsi::setChannel(indexInt, packageInt, channelInt);
    }
    else
    {
        auto infoCmd = (options)["info"];
        if(infoCmd == "true")
        {
            ncsi::getInfo(indexInt, packageInt);
        }
    }
    return 0;
}

