#!/usr/bin/env python

from subprocess import call
import sys
import subprocess
import dbus
import string
import socket
import os
import fcntl
import time
import glib
import gobject
import dbus.service
import dbus.mainloop.glib

DBUS_NAME = 'org.openbmc.LogManager'
ERRL_INTF_NAME = 'org.openbmc.Errl'
SRVC_INTF_NAME = 'org.openbmc.Service'
OBJ_NAME_RSYSLOG = '/org/openbmc/LogManager/rsyslog'

'''
    Object Path > /org/openbmc/LogManager/rsyslog
        Interface:Method > org.openbmc.Service.Enable dict:string:string
        Interface:Method > org.openbmc.Service.Disable
'''

class JournalUtils ():
    def _isvalidip(self, family, ipaddr):
        if family == socket.AF_INET:
            try:
                socket.inet_pton(socket.AF_INET, ipaddr)
            except AttributeError:  # no inet_pton here, sorry
                try:
                    socket.inet_aton(ipaddr)
                except socket.error:
                    return False
                return ipaddr.count('.') == 3
            except socket.error:  # not a valid address
                return False

            return True

        elif family == socket.AF_INET6:
            try:
                socket.inet_pton(socket.AF_INET6, ipaddr)
            except socket.error:  # not a valid address
                return False
            return True

        else: return False

class Rsyslog (dbus.service.Object):
    def __init__(self, bus, name):
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self,bus,name)

    @dbus.service.method(dbus.PROPERTIES_IFACE, "ss", "v")
    def Get(self, iface, ppty):
        return self.GetAll(iface)[ppty]

    @dbus.service.method(dbus.PROPERTIES_IFACE, 's', 'a{sv}')
    def GetAll(self, iface):
        if iface == ERRL_INTF_NAME:
            status, remote_ip, remote_port = self.Status()
            return {'status': status, 'ipaddr': remote_ip, 'port': remote_port }
        else:
            raise dbus.exceptions.DBusException('org.openbmc.UnknownInterface',
                                'This object does not implement the %s interface' % iface)

    @dbus.service.method(SRVC_INTF_NAME, "a{sv}", "x")
    def Enable (self, argv_dict):
        remote_ip = ""
        remote_port = 0

        params = len (argv_dict)
        if params > 2 : ValueError("Invalid Parameters")

        for property_name in argv_dict:
            if property_name == "ipaddr":
                remote_ip = argv_dict [property_name]
            elif property_name == "port":
                remote_port = argv_dict [property_name]
            else: 
                raise ValueError("Invalid Argument: IP Address/Port expected.")

        if not remote_ip: 
            cur_remote = self._GetConfig ('Remote')
            if not cur_remote: 
                raise ValueError("Invalid Remote Syslog IP Address")
            else:
                cur_remote = cur_remote[3:]
                remote_ip, port_str = cur_remote.split (":")
                remote_port = int(port_str)
        if not util._isvalidip (socket.AF_INET, remote_ip): raise ValueError, "Malformed IP Address"
        if not remote_port : remote_port = 514
        if remote_port > 65535 : raise ValueError("Invalid Remote Syslog Port")
        
        remote_addr = remote_ip + ":" + str(remote_port)
        r = self._ModifyService('Remote', remote_addr)

        cur_options = self._GetConfig ('Options')
        new_options = self._GetOptions()

        if cur_options != new_options:
            r = self._ModifyService('Options', new_options)
            r = self._RestartService ()

        return r

    @dbus.service.method(SRVC_INTF_NAME, "as", "x")
    def Disable (self, argv_list):
        params = len (argv_list)
        if params : ValueError("Invalid Parameters")

        remote = self._GetConfig ('Remote')
        if not remote : return 0

        r = self._ModifyService('Options', '-C') # FIXME: Restore current options minus the remote.
        r = self._RestartService ()
        return r

    def Status (self):
        remote = self._GetConfig ('Remote')
        if not remote : return ("Disabled", "0.0.0.0", 0)

        cur_remote = remote[3:]
        remote_ip, remote_port = cur_remote.split (":")
        
        options = self._GetConfig ('Options')
        if not options : return ("Disabled", remote_ip, remote_port)

        if remote in options : return ("Enabled", remote_ip, remote_port)

        return ("Disabled", remote_ip, remote_port)

    def _ModifyService (self, opt, val):
        if not os.path.isfile(syslog_service_bbx_file):
            r = call (["cp", syslog_service_lib_file, syslog_service_bbx_file])
            r = call (["ln", "-s", syslog_service_bbx_file, syslog_service_cfg_file])

        if not os.path.isfile(syslog_service_env_file):
            env_file = open(syslog_service_env_file, 'w')
            env_file.write ("OPTIONS=\"-C\"")
            env_file.close()

        if opt not in OptionKeys: raise ValueError("Invalid Option")

        self._ModifyParam (opt, val)

        return 0

    def _StopService (self):
        r = call (["systemctl", "stop", "syslog"])
        r = call (["systemctl", "--no-reload", "kill", "syslog"])
        return r

    def _StartService (self):
        r = call (["systemctl", "daemon-reload"])
        r = call (["systemctl", "start", "syslog"])
        return r

    def _RestartService (self):
        r = self._StopService()
        r = self._StartService()
        return r
    
    def _ModifyParam (self, opt, val):
        env_file = open(syslog_service_env_file, 'r') 
        tmp_file = open(syslog_service_tmp_file, 'w')

        optkey = OptionKeySwitchMap [opt]['key']
        for line in env_file:
            if line[0] == '#': 
                tmp_file.write(line)
                continue
            curkey = line.strip().split ("=")[0]
            if curkey != optkey : 
                tmp_file.write(line)

        tmp_file.write(optkey + "=\""  + OptionKeySwitchMap[opt]['switch'] + val + "\"" + "\n")

        env_file.close ()
        tmp_file.close ()

        r = call (["cp", syslog_service_tmp_file, syslog_service_env_file])
        return r

    def _GetConfig (self, opt):
        with open(syslog_service_env_file, "r") as f:
            for line in f:
                if line[0] == '#': continue
                config = line.split ("=")
                var = config [0]
                if var == OptionKeySwitchMap[opt]['key']:
                    val = config [1]
                    val = val[1:-2] # FIXME: Why is there a trailing space ???
                    return val
        return ""

    def _GetOptions(self):
        cfg = {}
        i = 0

        for opt in OptionKeys:
            if opt == 'Options' : continue
            cfg [i] = self._GetConfig(opt)
            i+=1
            
        options = ''
        j = 0
        while j<i-1:
            if cfg[j] : options += cfg [j]
            j+=1

        return options

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(DBUS_NAME, bus)

    global util
    global rsys
    global syslog_service_lib_file
    global syslog_service_bbx_file
    global syslog_service_cfg_file
    global syslog_service_env_file
    global syslog_service_tmp_file
    global OptionKeys
    global OptionKeySwitchMap

    OptionKeys = ['Options', 'Outfile', 'Priority', 'Smaller', 'RotateSize', 'RotateNum', 'Remote', 'LocalAndNet', 'DropDup', 'SharedMem', 'ConfFile', 'MarkTime', 'Printk']
    OptionKeySwitchMap = {
        'Options'       : { 'switch' : "",    'key' : "OPTIONS" },
        'Outfile'       : { 'switch' : "-O ", 'key' : "OBMC_SYSLOG_OUTFILE" },
        'Priority'      : { 'switch' : "-O ", 'key' : "OBMC_SYSLOG_PRIORITY" },
        'Smaller'       : { 'switch' : "-S ", 'key' : "OBMC_SYSLOG_SMALLER" },
        'RotateSize'    : { 'switch' : "-s ", 'key' : "OBMC_SYSLOG_ROTATESIZE" },
        'RotateNum'     : { 'switch' : "-b ", 'key' : "OBMC_SYSLOG_ROTATENUM" },
        'Remote'        : { 'switch' : "-R ", 'key' : "OBMC_SYSLOG_REMOTE" },
        'LocalAndNet'   : { 'switch' : "-L ", 'key' : "OBMC_SYSLOG_LOCALNET" },
        'DropDup'       : { 'switch' : "-D ", 'key' : "OBMC_SYSLOG_DROPDUP" },
        'SharedMem'     : { 'switch' : "-C ", 'key' : "OBMC_SYSLOG_SHAREDMEM" },
        'ConfFile'      : { 'switch' : "-f ", 'key' : "OBMC_SYSLOG_CONFFILE" },
        'MarkTime'      : { 'switch' : "-m ", 'key' : "OBMC_SYSLOG_MARKTIME" },
        'Printk'        : { 'switch' : "-K ", 'key' : "OBMC_SYSLOG_PRINTK" }
    }

    syslog_service_lib_file = '/lib/systemd/system/busybox-syslog.service'
    syslog_service_bbx_file = '/etc/systemd/system/busybox-syslog.service'
    syslog_service_cfg_file = '/etc/systemd/system/syslog.service'
    syslog_service_env_file = '/etc/default/busybox-syslog'
    syslog_service_tmp_file = '/tmp/busybox-syslog.tmp'

    util    = JournalUtils ()
    rsys    = Rsyslog (bus, OBJ_NAME_RSYSLOG)

    mainloop = gobject.MainLoop()
    print("Started")
    mainloop.run()

if __name__ == '__main__':
    sys.exit(main())

