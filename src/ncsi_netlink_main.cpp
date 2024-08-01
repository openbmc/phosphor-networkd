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
#include "ncsi_util.hpp"

#include <phosphor-logging/lg2.hpp>

#include <string>
#include <vector>

static void exitWithError(const char* err, char** argv)
{
    phosphor::network::ncsi::ArgumentParser::usage(argv);
    lg2::error("ERROR: {ERROR}", "ERROR", err);
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv)
{
    using namespace phosphor::network;
    using namespace phosphor::network::ncsi;
    // Read arguments.
    auto options = ArgumentParser(argc, argv);
    int packageInt{};
    int channelInt{};
    int indexInt{};
    int operationInt{DEFAULT_VALUE};
    int AENInt{};

    // Parse out interface argument.
    auto ifIndex = (options)["index"];
    try
    {
        indexInt = stoi(ifIndex, nullptr);
    }
    catch (const std::exception& e)
    {
        exitWithError("Interface not specified.", argv);
    }

    if (indexInt < 0)
    {
        exitWithError("Interface value should be greater than equal to 0",
                      argv);
    }

    // Parse out package argument.
    auto package = (options)["package"];
    try
    {
        packageInt = stoi(package, nullptr);
    }
    catch (const std::exception& e)
    {
        packageInt = DEFAULT_VALUE;
    }

    if (packageInt < 0)
    {
        packageInt = DEFAULT_VALUE;
    }

    // Parse out channel argument.
    auto channel = (options)["channel"];
    try
    {
        channelInt = stoi(channel, nullptr);
    }
    catch (const std::exception& e)
    {
        channelInt = DEFAULT_VALUE;
    }

    if (channelInt < 0)
    {
        channelInt = DEFAULT_VALUE;
    }

    auto payloadStr = (options)["oem-payload"];
    if (!payloadStr.empty())
    {
        std::string byte(2, '\0');
        std::vector<unsigned char> payload;

        if (payloadStr.size() % 2)
            exitWithError("Payload invalid: specify two hex digits per byte.",
                          argv);

        // Parse the payload string (e.g. "50000001572100") to byte data
        // The first two characters (i.e. "50") represent the Send Cmd Operation
        // All remaining pairs, interpreted in hex radix, represent the command
        // payload
        int sendCmdSelect{};
        for (unsigned int i = 1; i < payloadStr.size(); i += 2)
        {
            byte[0] = payloadStr[i - 1];
            byte[1] = payloadStr[i];

            try
            {
                sendCmdSelect = stoi(byte, nullptr, 16);
            }
            catch (const std::exception& e)
            {
                exitWithError("Payload invalid.", argv);
            }
            if (i == 1)
            {
                operationInt = sendCmdSelect;
            }
            else
            {
                payload.push_back(sendCmdSelect);
            }
        }

        if (operationInt == DEFAULT_VALUE)
        {
            exitWithError("No payload specified.", argv);
        }

        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }

        return ncsi::sendOemCommand(
            indexInt, packageInt, channelInt, operationInt,
            std::span<const unsigned char>(payload.begin(), payload.end()));
    }
    else if ((options)["set"] == "true")
    {
        // Can not perform set operation without package.
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }
        return ncsi::setChannel(indexInt, packageInt, channelInt);
    }
    else if ((options)["info"] == "true")
    {
        return ncsi::getInfo(indexInt, packageInt);
    }
    else if ((options)["clear"] == "true")
    {
        return ncsi::clearInterface(indexInt);
    }
    else if ((options)["AEN"] != ArgumentParser::emptyString)
    {
        auto AEN = stoi((options)["AEN"], nullptr);
        if (AEN < 0 || AEN > 7)
        {
            exitWithError("AEN value must be between 0 and 7", argv);
        }
        else
        {
            switch (AEN)
            {
                case 0:
                    AENInt = disableAENMask;
                    break;
                case 1:
                    AENInt = enableLinkAENMask;
                    break;
                case 2:
                    AENInt = enableLinkConfigAENMask;
                    break;
                case 3:
                    AENInt = enableLinkNCdriverAENMask;
                    break;
                case 4:
                    AENInt = enableConfigAENMask;
                    break;
                case 5:
                    AENInt = enableConfigNCdriverAENMask;
                    break;
                case 6:
                    AENInt = enableHostNCdriverAENMask;
                    break;
                case 7:
                    AENInt = enableAENMask;
                    break;
                default:
                    // Additional check for negative case
                    exitWithError("Invalid AEN value", argv);
                    break;
            }
        }
        return ncsi::aenEnable(indexInt, packageInt, channelInt, AENInt);
    }
    else
    {
        exitWithError("No Command specified", argv);
    }
    return 0;
}
