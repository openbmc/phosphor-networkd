# Network Management

## Overview

A Network Manager is a daemon which handles network management operations. It
must implement the `xyz.openbmc_project.Network.SystemConfiguration.interface`
and `org.freedesktop.DBus.ObjectManager`.

When the network manager daemon comes up, it should create objects implementing
physical link/virtual interfaces such as
`xyz.openbmc_project.Network.EthernetInterface` or
`xyz.openbmc_project.Network.VLANInterface` on the system.

IP address(v4 and v6) objects must be children objects of the physical/virtual
interface object.

## Interfaces

1. SystemConfiguration: This describes the system-specific parameters.
2. EthernetInterface: This describes the interface-specific parameters.
3. IP: This describes the IP address-specific parameters.
4. IPProtocol: This describes the IP protocol type (IPv4/IPv6).
5. VLANInterface: This describes the VLAN-specific properties.
6. Bond: This describes the interface bonding parameters.

## DbusObjects

### Interface Objects

Interface objects can be physical as well as virtual.

If the object is a physical interface, it can't be deleted, but if it is a
virtual interface object it can be deleted.

Example: `/xyz/openbmc_project/network/eth0`

### IPAddress Objects

There can be multiple IP address objects under an interface object. These
objects can be deleted by the delete function.

IP address objects (both IPv4 and IPv6) reside directly under the interface
object path, with the IP address and prefix length encoded using sdbusplus
path escaping.

Example IPv4: `/xyz/openbmc_project/network/eth0/_3192_2e168_2e1_2e1_2f24`
(for address `192.168.1.1/24`)

Example IPv6: `/xyz/openbmc_project/network/eth0/_32001_3adb8_3a1_3a_3a1_2f64`
(for address `2001:db8:1::1/64`)

Use `busctl tree xyz.openbmc_project.Network` to list all current IP objects.

### Conf Object

This object will have the system configuration related parameters.

Example: `/xyz/openbmc_project/network/config`

## UseCases

### Configure IP address

```sh
busctl call xyz.openbmc_project.Network /xyz/openbmc_project/network/<interface>
xyz.openbmc_project.Network.IP.Create IP ssys
"xyz.openbmc_project.Network.IP.Protocol.IPv4" "<ip>" <subnetmask>
"<networkgateway>"

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X POST -d
'{"data":["xyz.openbmc_project.Network.IP.Protocol.IPv4","<ip>",<subnetmask>,"<networkGateway>"]
}' https://<hostname/ip>/xyz/openbmc_project/network/eth0/action/IP
```

### Configure Default Gateway

#### Get

```sh
busctl get-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/<interface>
xyz.openbmc_project.Network.EthernetInterface DefaultGateway

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X GET
https://<hostname/ip>/xyz/openbmc_project/network/config/attr/DefaultGateway
```

#### Set

```sh
busctl set-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/<interface>
xyz.openbmc_project.Network.EthernetInterface DefaultGateway s
"<DefaultGateway>"

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X PUT -d '{"data":
"x.x.x.x"}'
https://<hostname/ip>/xyz/openbmc_project/network/config/attr/DefaultGateway
```

NOTE: Since the system does not allow unpingable gateway address, make sure the
gateway address is pingable.

### Configure HostName

#### Get

```sh
busctl get-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/config
xyz.openbmc_project.Network.SystemConfiguration HostName

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X GET
https://<hostname/ip>/xyz/openbmc_project/network/config/attr/HostName
```

#### Set

```sh
busctl set-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/config
xyz.openbmc_project.Network.SystemConfiguration HostName s "<HostName>"

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X PUT -d '{"data":
"<hostname>"}'
https://<hostname/ip>/xyz/openbmc_project/network/config/attr/HostName
```

### Delete IP address

```sh
busctl call xyz.openbmc_project.Network
/xyz/openbmc_project/network/<interface>/<encoded-ip-prefix>
xyz.openbmc_project.Object.Delete Delete
```

NOTE: The path component encodes the IP address and prefix length (e.g.
`192.168.1.1/24` -> `_3192_2e168_2e1_2e1_2f24`). Use `busctl tree
xyz.openbmc_project.Network` to list the exact object paths.

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/json" -X DELETE
https://<hostname/ip>/xyz/openbmc_project/network/eth0/ipv4/fbfc29b
```

### Configure DHCP

#### Get

```sh
busctl get-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/<interface> xyz.openbmc_project.Network.EthernetInterface
DHCPEnabled

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X GET
https://<hostname/ip>/xyz/openbmc_project/network/eth0/attr/DHCPEnabled
```

#### Set

```sh
busctl set-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/<interface> xyz.openbmc_project.Network.EthernetInterface
DHCPEnabled s "<DHCP State>"

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X PUT -d '{"data":
1}' https://<hostname/ip>/xyz/openbmc_project/network/eth0/attr/DHCPEnabled
```

### Configure MACAddress

#### Get

```sh
busctl get-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/eth0 xyz.openbmc_project.Network.MACAddress
MACAddress

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X GET
https://<hostname/ip>/xyz/openbmc_project/network/eth0/attr/MACAddress
```

#### Set

NOTE: MAC address should be LOCAL ADMIN MAC (2nd bit of first byte should be
on).

```sh
busctl set-property xyz.openbmc_project.Network
/xyz/openbmc_project/network/eth0 xyz.openbmc_project.Network.MACAddress
MACAddress s "XX:XX:XX:XX:XX:XX"

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X PUT -d '{"data":
"XX:XX:XX:XX:XX:XX" }'
https://<hostname/ip>/xyz/openbmc_project/network/eth0/attr/MACAddress
```

### Network factory reset

```sh
busctl call xyz.openbmc_project.Network /xyz/openbmc_project/network
xyz.openbmc_project.Common.FactoryReset Reset

curl -c cjar -b cjar -k -H "Content-Type: application/json" -X POST -d
'{"data":[] }' https://<hostname/ip>/xyz/openbmc_project/network/action/Reset
```

### VLAN

#### Create

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/json" -X POST -d
'{"data":["eth0",50] }'
https://<hostname/ip>/xyz/openbmc_project/network/action/VLAN
```

#### Delete

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/json" -X DELETE
https://<hostname/ip>/xyz/openbmc_project/network/eth0_50

busctl call xyz.openbmc_project.Network /xyz/openbmc_project/network/eth0_50
xyz.openbmc_project.Object.Delete Delete
```

#### Enumerate

```sh
curl -c cjar -b cjar -k -H "Content-Type: application/json" -X GET
https://<hostname/ip>/xyz/openbmc_project/network/eth0_50/enumerate
```

#### Configure IP on VLAN Interface

Please refer to the "Configure IP address" section.
