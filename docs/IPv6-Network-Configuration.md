# IPv6 Network Configuration

This document covers the various configuration options available on BMC to set the ethernet interface to IPv6 network


## Factory Default configuration

```
[Network]
DHCP=true

[DHCP]
ClientIdentifier=mac
UseDNS=true
UseDomains=true
UseNTP=true
UseHostname=true
SendHostname=true

[IPv6AcceptRA]
DHCPv6Client=true
```
The Dynamic IPv6 (DHCPv6) and the related NTP, DNS and Hostname capabilities are enabled by default. 

`IPv6AcceptRA = @ENABLE_IPV6_ACCEPT_RA@`

This is a compiler directive set via system specific recipe. 
When set to true: BMC's ethernet interface will be set to accept the IPv6 router advertised network parameters in the local subnet; provided BMC is booted in a network with an active IPv6 router. This is the Stateless DHCPv6 referred as SLAAC network.

## Static IPv6 configuration

BMC interface can be configured with the Static IPv6 network. This takes the address and prefix length as input parameters.

Dbus:

`busctl call  xyz.openbmc_project.Network /xyz/openbmc_project/network/eth1 xyz.openbmc_project.Network.IP.Create IP ssys "xyz.openbmc_project.Network.IP.Protocol.IPv6" "2002:903:15F:325:192:168:122:184"  64 ""`

Redfish:

`PATCH https://${bmc}/redfish/v1/Managers/bmc/EthernetInterfaces/<intf> -d '{"IPv6StaticAddresses": [{"Address": "2002:903:15F:325:192:168:122:184","PrefixLength": 24}]}'`

## Static IPv6 Gateway configuration

IPv6 supports multiple static gateways on single interface. This is a separate object in the BMC, which is created using below commands. To add a static default gateway, the Destination address will be "::".

Dbus:

`busctl call  xyz.openbmc_project.Network /xyz/openbmc_project/network/eth1 xyz.openbmc_project.Network.StaticRoute.Create StaticRoute ssys "::" "2002:903:15F:325:192:168:122:1" 64 "xyz.openbmc_project.Network.IP.Protocol.IPv6"`

Redfish:

`PATCH https://${bmc}/redfish/v1/Managers/bmc/EthernetInterfaces/<intf> -d '{"IPv6StaticDefaultGateways": [{"Address": "2002:903:15F:325:192:168:122:1","PrefixLength": 24}]}'`

## Dynamic IPv6 configuration

This is the default setting of the network interface. BMC can acquire two types of dynamic networks. Stateless and Statefull. Stateless settings needs an IPv6 router in the local network. Statefull settings needs an active DHCPv6 server running in the local network.

Reference: rfc8415

#### Stateless DHCPv6/SLAAC

This enables BMC to apply the IPv6 router sent parameters on to the interface. Router sends the IPAddress, PrefixLength and Gateway 

Dbus:

`busctl set-property xyz.openbmc_project.Network /xyz/openbmc_project/network/eth0 xyz.openbmc_project.Network.EthernetInterface IPv6AcceptRA  b true`

Redfish:

`PATCH https://$bmc/redfish/v1/Managers/bmc/EthernetInterfaces/<intf> -d '{"StatelessAddressAutoConfig" : {"IPv6AutoConfigEnabled": true}}'`

#### Stateful DHCPv6

Dbus:

`busctl set-property xyz.openbmc_project.Network /xyz/openbmc_project/network/eth0 xyz.openbmc_project.Network.EthernetInterface DHCPEnabled s "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.v6" (without DHCPv4)`

`busctl set-property xyz.openbmc_project.Network /xyz/openbmc_project/network/eth0 xyz.openbmc_project.Network.EthernetInterface DHCPEnabled s "xyz.openbmc_project.Network.EthernetInterface.DHCPConf.both" (with DHCPv4)`

Redfish:

`PATCH https://$bmc/redfish/v1/Managers/bmc/EthernetInterfaces/<intf> -d '{"DHCPv6": {"OperatingMode": "Enabled" }}' `

##### With Router Advertisement

Scenario: BMC  placed in a network where the IPv6 capable router and DHCPv6 server are active.

This is the case where the flag IPv6AcceptRA is enabled. BMC receives the Router Advertisement(RA) packets, the RA packets are processed, and the A, M and O bits are read. According to the combinational settings of these bits, BMC will start the DHCPv6 client. DHCPv6 client will start sending out the Solicit packets to fetch the relevant network parameters from the DHCPv6 server.

##### Without Router Advertisement

Scenario: BMC  placed in a network where DHCPv6 server are active, without an IPv6 capable router. 

This is the case where the flag IPv6AcceptRA is disabled & DHCPv6 setting has WithoutRA=solicit. BMC will start the DHCPv6 client without a trigger from an incoming RA packet. DHCPv6 client will start sending out the Solicit packets to fetch all the dynamic IPv6 network parameters from the DHCPv6 server.

