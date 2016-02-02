#!/usr/bin/env python

from subprocess import call
import sys
import subprocess
import dbus
import string
import os
import fcntl
import glib
import gobject
import dbus.service
import dbus.mainloop.glib

DBUS_NAME = 'org.openbmc.NetworkManager'
OBJ_NAME = '/org/openbmc/NetworkManager/Interface'

network_providers = {
	'networkd' : { 
		'bus_name' : 'org.freedesktop.network1',
		'ip_object_name' : '/org/freedesktop/network1/network/default',
		'hw_object_name' : '/org/freedesktop/network1/link/_31',
		'interface_name' : 'org.freedesktop.network1.Network',
		'method' : 'org.freedesktop.network1.Network.SetAddr'
	},
	'NetworkManager' : {
		'bus_name' : 'org.freedesktop.NetworkManager',
		'ip_object_name' : '/org/freedesktop/NetworkManager',
		'hw_object_name' : '/org/freedesktop/NetworkManager',
		'interface_name' : 'org.freedesktop.NetworkManager',
		'method' : 'org.freedesktop.NetworkManager' # FIXME: 
	},	
}

def getPrefixLen(mask):
	prefixLen = sum([bin(int(x)).count('1') for x in mask.split('.')])
	return prefixLen

class IfAddr ():
    def __init__ (self, family, scope, flags, prefixlen, addr, gw):
        self.family     = family
        self.scope      = scope
        self.flags      = flags
        self.prefixlen  = prefixlen
        self.addr       = addr
        self.gw         = gw

class NetMan (dbus.service.Object):
    def __init__(self, bus, name):
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self,bus,name)

    def setNetworkProvider(self, provider):
        self.provider = provider

    def _setAddr (self, op, device, ipaddr, netmask, family, flags, scope, gateway):
        netprov     = network_providers [self.provider]
        bus_name    = netprov ['bus_name']
        obj_path    = netprov ['ip_object_name']
        intf_name   = netprov ['interface_name']

        obj = self.bus.get_object(bus_name, obj_path)
        intf = dbus.Interface(obj, intf_name)
        if (op == "add"):
            return intf.AddAddress (device, ipaddr, netmask, family, flags, scope, gateway)

        if (op == "del"):
            return intf.DelAddress (device, ipaddr, netmask, family, flags, scope, gateway)

    def _getAddr (self, target, device):
        netprov     = network_providers [self.provider]
        bus_name    = netprov ['bus_name']

        if (target == "ip"):
            intf_name   = 'org.freedesktop.network1.Network'
            obj_path    = netprov ['ip_object_name']
            obj = self.bus.get_object(bus_name, obj_path)
            intf = dbus.Interface(obj, intf_name)
            return intf.GetAddress (device)

        if (target == "mac"):
            intf_name   = 'org.freedesktop.network1.Link'
            obj_path    = netprov ['hw_object_name']
            obj = self.bus.get_object(bus_name, obj_path)
            intf = dbus.Interface(obj, intf_name)
            mac = intf.GetAddress (device)
            print mac
            return mac



    @dbus.service.method(DBUS_NAME, "", "")
    def test(self):
        print("TEST")

    @dbus.service.method(DBUS_NAME, "ssss", "x")
    def AddAddress4 (self, device, ipaddr, netmask, gateway):
        prefixLen = getPrefixLen (netmask)
        confFile = "/etc/systemd/network/10-bmc-" + device + ".network"

        print("Making .network file...")
        networkconf = open (confFile, "w+") 
        networkconf.write ('[Match]'+ '\n')
        networkconf.write ('Name=' + (device) + '\n')
        networkconf.write ('[Network]' + '\n')
        networkconf.write ('Address=' + ipaddr + '/' + str(prefixLen) +  '\n')
        networkconf.write ('Gateway=' + gateway + '\n')
        networkconf.close()

        print("Restarting networkd service...")
        call(["ip", "addr", "flush", device])
        return 0
        #return self._setAddr ("add", device, ipaddr, netmask, 2, 0, 253, gateway

    @dbus.service.method(DBUS_NAME, "ssss", "x")
    def DelAddress4 (self, device, ipaddr, netmask, gateway):
        prefixLen = getPrefixLen (netmask)
        confFile = "/etc/systemd/network/10-bmc-" + device + ".network"
        if not (os.path.exists(confFile)):
            return 1

        self._setAddr ("del", device, ipaddr, netmask, 2, 0, 253, gateway)
        os.remove (confFile)
        return  0;

    @dbus.service.method(DBUS_NAME, "s", "a(iyyus)s")
    def GetAddress4 (self, device):
        return self._getAddr ("ip", device)

    @dbus.service.method(DBUS_NAME, "s", "s")
    def GetHwAddress (self, device):
        return self._getAddr ("mac", device)

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(DBUS_NAME, bus)
    obj = NetMan (bus, OBJ_NAME)
    obj.setNetworkProvider ("networkd")
    mainloop = gobject.MainLoop()
    print("Started")
    mainloop.run()

if __name__ == '__main__':
    sys.exit(main())
