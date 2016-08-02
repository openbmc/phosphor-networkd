#!/usr/bin/env python

from subprocess import call, Popen, PIPE
from IPy import IP
import sys
import subprocess
import dbus
import string
import socket
import re
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
        'ip_if_name' : 'org.freedesktop.network1.Network',
        'hw_if_name' : 'org.freedesktop.network1.Link',
        'method' : 'org.freedesktop.network1.Network.SetAddr'
    },
    'NetworkManager' : {
        'bus_name' : 'org.freedesktop.NetworkManager',
        'ip_object_name' : '/org/freedesktop/NetworkManager',
        'hw_object_name' : '/org/freedesktop/NetworkManager',
        'ip_if_name' : 'org.freedesktop.NetworkManager',
        'hw_if_name' : 'org.freedesktop.NetworkManager',
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

    def _isvaliddev(self, device):
        devices = os.listdir ("/sys/class/net")
        if not device in devices : return False
        else: return True

    def _ishwdev (self, device):
        f = open ("/sys/class/net/"+device+"/type")
        type = f.read()
        return False if (int(type) ==  772) else True

    def _isvalidmask (self, mask):
        for x in mask.split('.'):
            try:
                y = int(x)
            except:
                return False
            if y > 255: return False
        return mask.count('.') == 3

    def _isvalidmac(self, mac):
        macre = '([a-fA-F0-9]{2}[:|\-]?){6}'
        if re.compile(macre).search(mac) : return True
        else: return False

    def _isvalidipv4(self, ipstr, netmask):
        ip_parts = ipstr.split(".")
        if len(ip_parts) != 4:
            return "Malformed"

        first, second, third, fourth = [int(part) for part in ip_parts]
        if first == 0 and second == 0 and third == 0 and fourth == 0:
            return "Invalid" 	# "this" network disallowed
        if first == 169 and second == 254:
            return "Link Local"
        if first >= 224:
            return "Invalid"	# class D multicast and class E disallowed
        if first == 192 and second == 88 and third == 99:
            return "Invalid"	# ipv6 relay

        # check validity against netmask
        if netmask != '0':
            ip_bin = (first << 24) + (second << 16) + (third << 8) + fourth
            mask_parts = netmask.split(".")
            if len(mask_parts) == 4:	# long form netmask
                mask_bin = (int(mask_parts[0]) << 24) + (int(mask_parts[1]) << 16) + (int(mask_parts[2]) << 8) + int(mask_parts[3])
            elif netmask.count(".") == 0:	# short form netmask
                mask_bin = 0xffffffff ^ (1 << 32 - int(netmask)) - 1
            else:
                return "Malformed"	# bad netmask

            if ip_bin & ~mask_bin == 0:
                return "Invalid"	# disallowed by this netmask
            if ip_bin | mask_bin == 0xFFFFFFFF:
                return "Invalid"	# disallowed by this netmask

        return "Valid"


    def _isvalidip(self, ipaddr, netmask = '0'):
        try:
            ip = IP(ipaddr)
        except ValueError:
            return "Malformed"

        ipstr = ip.strNormal(0)
        ipstr_masked = ip.strNormal(2)
        if ipstr_masked.count("/") != 0 and netmask == '0':
            netmask = ipstr_masked.split("/")[1]

        if ip.version() == 4:	# additional checks for ipv4
            return self._isvalidipv4(ipstr, netmask)
        # TODO: check ipv6 openbmc/openbmc#496

        return "Valid"

    def _getAddr (self, target, device):
        netprov     = network_providers [self.provider]
        bus_name    = netprov ['bus_name']

        if (target == "ip"):
            ipaddr = ""
            defgw = ""
            prefixlen = "0"

            proc = subprocess.Popen(["ip", "addr", "show", "dev", device], stdout=PIPE)
            procout = proc.communicate()
            if procout: 
                ipout = procout[0].splitlines()[2].strip()
                ipaddr,prefixlen = ipout.split ()[1].split("/")

            proc = subprocess.Popen(["ip", "route", "show", "dev", device, "default", "0.0.0.0/0"], stdout=PIPE)
            procout = proc.communicate()
            if procout[0]:
                ipout = procout[0].splitlines()[0].strip()
                defgw = ipout.split ()[2]

            return 2, int(prefixlen), ipaddr, defgw

        if (target == "mac"):
            proc = subprocess.Popen(["ip", "link", "show", "dev", device], stdout=PIPE)
            ipout = proc.communicate()[0].splitlines()[1].strip()
            mac = ipout.split ()[1]
            return mac

    @dbus.service.method(DBUS_NAME, "", "")
    def test(self):
        print("TEST")

    @dbus.service.method(DBUS_NAME, "s", "x")
    def EnableDHCP (self, device):
        if not self._isvaliddev (device) : raise ValueError, "Invalid Device"

        confFile = "/etc/systemd/network/00-bmc-" + device + ".network"

        print("Making .network file...")
        try:
            networkconf = open (confFile, "w+") 
        except IOError:
            raise IOError, "Failed to open " + confFile
            
        networkconf.write ('[Match]'+ '\n')
        networkconf.write ('Name=' + (device) + '\n')
        networkconf.write ('[Network]' + '\n')
        networkconf.write ('DHCP=yes')
        networkconf.close ()

        print("Restarting networkd service...")
        rc = call(["ip", "addr", "flush", device])
        rc = call(["systemctl", "restart", "systemd-networkd.service"])
        return rc

    @dbus.service.method(DBUS_NAME, "ssss", "x")
    def SetAddress4 (self, device, ipaddr, netmask, gateway):
        if not self._isvaliddev (device) : raise ValueError, "Invalid Device"
        if not self._isvalidmask (netmask) : raise ValueError, "Invalid Mask"
        prefixLen = getPrefixLen (netmask)
        if prefixLen == 0: raise ValueError, "Invalid Mask"
        valid = self._isvalidip (ipaddr, netmask)
        if valid != "Valid": raise ValueError, valid + " IP Address"
        valid = self._isvalidip (gateway)
        if valid != "Valid": raise ValueError, valid + " IP Address"

        confFile = "/etc/systemd/network/00-bmc-" + device + ".network"

        print("Making .network file...")
        try:
            networkconf = open (confFile, "w+") 
        except IOError:
            raise IOError, "Failed to open " + confFile

        networkconf.write ('[Match]'+ '\n')
        networkconf.write ('Name=' + (device) + '\n')
        networkconf.write ('[Network]' + '\n')
        networkconf.write ('Address=' + ipaddr + '/' + str(prefixLen) +  '\n')
        networkconf.write ('Gateway=' + gateway + '\n')
        networkconf.close()

        print("Restarting networkd service...")
        rc = call(["ip", "addr", "flush", device])
        rc = call(["systemctl", "restart", "systemd-networkd.service"])
        return rc

    @dbus.service.method(DBUS_NAME, "s", "s")
    def GetAddressType (self, device):
        if not self._isvaliddev (device) : raise ValueError, "Invalid Device"

        confFile = "/etc/systemd/network/00-bmc-" + device + ".network"
        if not os.path.exists(confFile): 
            print "Config file (%s) not found !" % confFile
            netprov     = network_providers [self.provider]
            bus_name    = netprov ['bus_name']
            obj_name    = netprov ['ip_object_name']
            o = self.bus.get_object(bus_name, obj_name, introspect=False)
            i = dbus.Interface(o, 'org.freedesktop.DBus.Properties')
            f = i.Get (netprov ['ip_if_name'], "SourcePath")
            print "Using default networkd config file (%s)" % f
            confFile = f

        with open(confFile, "r") as f:
            for line in f:
                config = line.split ("=")
                if (len (config) < 2) : continue
                if config [0].upper() == "DHCP":
                    v = config[1].strip().upper()
                    if (v=="YES" or v=="IPV4" or v=="IPV6"):
                        return "DHCP"
        return "STATIC"

    #family, prefixlen, ip, defgw
    @dbus.service.method(DBUS_NAME, "s", "iyss")
    def GetAddress4 (self, device):
        if not self._isvaliddev (device) : raise ValueError, "Invalid Device"
        return self._getAddr ("ip", device)

    @dbus.service.method(DBUS_NAME, "s", "s")
    def GetHwAddress (self, device):
        if not self._isvaliddev (device) : raise ValueError, "Invalid Device"
        return self._getAddr ("mac", device)

    @dbus.service.method(DBUS_NAME, "ss", "i")
    def SetHwAddress (self, device, mac):
        if not self._isvaliddev (device) : raise ValueError, "Invalid Device"
        if not self._ishwdev (device) : raise ValueError, "Not a Hardware Device"
        if not self._isvalidmac (mac) : raise ValueError, "Malformed MAC address"

        rc = subprocess.call(["fw_setenv", "ethaddr", mac])

        print("Restarting networkd service...")
        rc = call(["ip", "link", "set", "dev", device, "down"])
        rc = call(["ip", "link", "set", "dev", device, "address", mac])
        rc = call(["ip", "link", "set", "dev", device, "up"])

        rc = call(["systemctl", "restart", "systemd-networkd.service"])
        return rc

    #string of nameservers
    @dbus.service.method(DBUS_NAME,"s", "s")
    def SetNameServers (self, nameservers):
        dns_entry = nameservers.split()
        fail_msg = ''
        dhcp_auto = False
        file_opened = False
        if len(dns_entry) > 0:
            for dns in dns_entry:
                valid = self._isvalidip (dns)
                if valid != "Valid":
                    if dns == "DHCP_AUTO=":
                        #This DNS is supplied by DHCP.
                        dhcp_auto = True
                    else:
                        print valid + " DNS Address [" + dns + "]"
                        fail_msg = fail_msg + '[' + dns + ']'
                else:
                    #Only over write on a first valid input
                    if file_opened == False:
                        resolv_conf = open("/etc/resolv.conf",'w')
                        file_opened = True
                        if dhcp_auto == True:
                            resolv_conf.write("### Generated automatically via DHCP ###\n")
                        else:
                            resolv_conf.write("### Generated manually via dbus settings ###\n")
                    dns_ip = 'nameserver ' + dns + '\n'
                    resolv_conf.write(dns_ip)
            if file_opened == True:
                resolv_conf.close()
        else:
            raise ValueError, "Invalid DNS entry"
        if len(fail_msg) > 0:
            return 'Failures encountered processing' + fail_msg
        else:
            return "DNS entries updated Successfully"

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
