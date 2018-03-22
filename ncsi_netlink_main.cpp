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
    // Read arguments.
    auto options = phosphor::network::ArgumentParser(argc, argv);

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

    auto index = (options)["index"];
    auto indexInt = atoi(index.c_str());
    if (indexInt < 0 )
    {
        exitWithError("Index not specified.", argv);
    }

  // TODO : Convert package and channel into integer
    //
    auto setCmd = (options)["set"];
    printf("CommnadString = %s\n", setCmd.c_str());
    if(setCmd == "true")
    {
        printf("set is being called\n");
        phosphor::network::ncsi::setInterface(indexInt, packageInt, channelInt);
    }

    auto infoCmd = (options)["info"];
    printf("InfoCommnadString = %s\n", infoCmd.c_str());
    if(infoCmd == "true")
    {
        printf("info is being called\n");
        phosphor::network::ncsi::getInfo(indexInt, packageInt);
    }
    return 0;
}

