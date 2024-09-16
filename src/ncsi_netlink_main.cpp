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

#include <linux/mctp.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/str/buf.hpp>

#include <string>
#include <vector>

static void exitWithError(const char* err, char** argv)
{
    phosphor::network::ncsi::ArgumentParser::usage(argv);
    lg2::error("ERROR: {ERROR}", "ERROR", err);
    exit(EXIT_FAILURE);
}

static void printInfo(phosphor::network::ncsi::InterfaceInfo& info)
{
    using namespace phosphor::network::ncsi;

    for (PackageInfo& pkg : info.packages)
    {
        lg2::debug("Package id : {ID}", "ID", pkg.id);
        if (pkg.forced)
        {
            lg2::debug("  package is forced");
        }
        for (ChannelInfo& chan : pkg.channels)
        {
            lg2::debug("    Channel id : {ID}", "ID", chan.id);
            if (chan.forced)
            {
                lg2::debug("    channel is forced");
            }
            if (chan.active)
            {
                lg2::debug("    channel is active");
            }

            lg2::debug("      version {MAJOR}.{MINOR} ({STR})", "MAJOR",
                       chan.version_major, "MINOR", chan.version_minor, "STR",
                       chan.version);

            lg2::debug("      link state {LINK}", "LINK", lg2::hex,
                       chan.link_state);

            auto& vlans = chan.vlan_ids;

            if (!vlans.empty())
            {
                lg2::debug("      Actve VLAN IDs:");
                for (uint16_t vlan : vlans)
                {
                    lg2::debug("        VID: {VLAN_ID}", "VLAN_ID", vlan);
                }
            }
        }
    }
}

static stdplus::StrBuf toHexStr(std::span<const uint8_t> c) noexcept
{
    stdplus::StrBuf ret;
    if (c.empty())
    {
        return ret;
    }
    stdplus::IntToStr<16, uint8_t> its;
    auto oit = ret.append(c.size() * 3);
    auto cit = c.begin();
    oit = its(oit, *cit++, 2);
    for (; cit != c.end(); ++cit)
    {
        *oit++ = ' ';
        oit = its(oit, *cit, 2);
    }
    *oit = 0;
    return ret;
}

struct MCTPAddress
{
    int network;
    uint8_t eid;
};

/* Parse a MCTP address string into network and EID components.
 *
 * A single int parses to just an EID, with MCTP_NET_ANY (which the
 * kernel will resolve to the default network).
 *
 * A comma-separated set of two ints will parse to a specific network
 * and EID.
 */
static MCTPAddress parseMCTPAddress(const std::string& str)
{
    std::string::size_type sep = str.find(',');
    std::string eid_str;
    MCTPAddress addr;

    if (sep == std::string::npos)
    {
        addr.network = MCTP_NET_ANY;
        eid_str = str;
    }
    else
    {
        std::string net_str = str.substr(0, sep);
        addr.network = stoi(net_str);
        eid_str = str.substr(sep + 1);
    }

    addr.eid = stoi(eid_str);

    return addr;
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
    NetlinkInterface* nl = nullptr;
    Interface* interface;

    // Parse out interface argument.
    auto ifIndex = (options)["index"];
    auto mctpAddrStr = (options)["mctp"];
    if (ifIndex != options.emptyString)
    {
        try
        {
            indexInt = stoi(ifIndex, nullptr);
        }
        catch (const std::exception& e)
        {
            exitWithError("Invalid interface specified.", argv);
        }

        if (indexInt < 0)
        {
            exitWithError("Interface value should be greater than equal to 0",
                          argv);
        }

        nl = new NetlinkInterface(indexInt);
        interface = nl;
    }
    else if (mctpAddrStr != options.emptyString)
    {
        MCTPAddress addr;
        try
        {
            addr = parseMCTPAddress(mctpAddrStr);
        }
        catch (const std::exception& e)
        {
            exitWithError("Invalid MCTP address specified.", argv);
        }

        interface = new MCTPInterface(addr.network, addr.eid);
    }
    else
    {
        exitWithError("An interface type (--index or --mctp) is required",
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

        if (!payload.empty())
        {
            lg2::debug("Payload: {PAYLOAD}", "PAYLOAD", toHexStr(payload));
        }

        std::optional<uint8_t> chan = channelInt != DEFAULT_VALUE
                                          ? std::make_optional(channelInt)
                                          : std::nullopt;
        NCSICommand cmd(operationInt, packageInt, chan, payload);

        auto resp = interface->sendCommand(cmd);
        if (!resp)
        {
            return EXIT_FAILURE;
        }
        lg2::debug("Response {DATA_LEN} bytes: {DATA}", "DATA_LEN",
                   resp->full_payload.size(), "DATA",
                   toHexStr(resp->full_payload));
    }
    else if ((options)["set"] == "true")
    {
        if (!nl)
        {
            exitWithError("Interface does not support set operation", argv);
        }
        // Can not perform set operation without package.
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package not specified.", argv);
        }
        return nl->setChannel(packageInt, channelInt);
    }
    else if ((options)["info"] == "true")
    {
        if (!nl)
        {
            exitWithError("Interface does not support info operation", argv);
        }

        auto info = nl->getInfo(packageInt);
        if (!info)
        {
            return EXIT_FAILURE;
        }
        printInfo(*info);
    }
    else if ((options)["clear"] == "true")
    {
        if (!nl)
        {
            exitWithError("Interface does not support clear operation", argv);
        }
        return nl->clearInterface();
    }
    else if (!(options)["pmask"].empty())
    {
        unsigned int mask{};
        try
        {
            size_t lastChar{};
            mask = std::stoul((options)["pmask"], &lastChar, 0);
            if (lastChar < (options["pmask"].size()))
            {
                exitWithError("Package mask value is not valid", argv);
            }
        }
        catch (const std::exception& e)
        {
            exitWithError("Package mask value is not valid", argv);
        }
        return nl->setPackageMask(mask);
    }
    else if (!(options)["cmask"].empty())
    {
        if (!nl)
        {
            exitWithError("Interface does not support channel mask operation",
                          argv);
        }
        if (packageInt == DEFAULT_VALUE)
        {
            exitWithError("Package is not specified", argv);
        }
        unsigned int mask{};
        try
        {
            size_t lastChar{};
            mask = stoul((options)["cmask"], &lastChar, 0);
            if (lastChar < (options["cmask"].size()))
            {
                exitWithError("Channel mask value is not valid", argv);
            }
        }
        catch (const std::exception& e)
        {
            exitWithError("Channel mask value is not valid", argv);
        }
        return nl->setChannelMask(packageInt, mask);
    }
    else
    {
        exitWithError("No Command specified", argv);
    }

    delete interface;

    return 0;
}
