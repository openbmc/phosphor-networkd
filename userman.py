#!/usr/bin/env python

from subprocess import call
import sys
import subprocess
import dbus
import string
import os
import fcntl
import time
import pexpect
import glib
import gobject
import dbus.service
import dbus.mainloop.glib

DBUS_NAME = 'org.openbmc.UserManager'
INTF_NAME = 'org.openbmc.Enrol'
OBJ_NAME_GROUPS = '/org/openbmc/UserManager/Groups'
OBJ_NAME_GROUP = '/org/openbmc/UserManager/Group'
OBJ_NAME_USERS = '/org/openbmc/UserManager/Users'
OBJ_NAME_USER = '/org/openbmc/UserManager/User'

'''
    Object Path > /org/openbmc/UserManager/Groups
        Interface:Method > org.openbmc.Enrol.GroupAddSys string:"groupname"
        Interface:Method > org.openbmc.Enrol.GroupAddUsr string:"groupname"
        Interface:Method > org.openbmc.Enrol.GroupList
    Object Path > /org/openbmc/UserManager/Group
        Interface:Method > org.openbmc.Enrol.GroupDel string:"groupname"
    Object Path > /org/openbmc/UserManager/Users
       Interface:Method > org.openbmc.Enrol.UserAdd string:"comment" string:"username" string:"groupname" string:"passwd"
        Interface:Method > org.openbmc.Enrol.UserList
    Object Path > /org/openbmc/UserManager/User
        Interface:Method > org.openbmc.Enrol.UserDel string:"username"
        Interface:Method > org.openbmc.Enrol.Passswd string:"username" string:"passwd"
'''

userman_providers = {
	'pam' : { 
		'adduser' : 'user add',
	},
	'ldap' : {
		'adduser' : 'ldap command to add user',
	},	
}

class UserManGroups (dbus.service.Object):
    def __init__(self, bus, name):
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self,bus,name)

    def setUsermanProvider(self, provider):
        self.provider = provider

    @dbus.service.method(INTF_NAME, "", "")
    def test(self):
        print("TEST")

    @dbus.service.method(INTF_NAME, "s", "x")
    def GroupAddUsr (self, groupname):
        r = call (["addgroup", groupname])
        return r

    @dbus.service.method(INTF_NAME, "s", "x")
    def GroupAddSys (self, groupname):
        r = call (["addgroup", "-S", groupname])
        return 0

    @dbus.service.method(INTF_NAME, "", "as")
    def GroupList (self):
        groupList = []
        with open("/etc/group", "r") as f:
            for grent in f:
                groupParams = grent.split (":")
                if (int(groupParams[2]) >= 1000 and int(groupParams[2]) != 65534):
                    groupList.append(groupParams[0])
        return groupList

class UserManGroup (dbus.service.Object):
    def __init__(self, bus, name):
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self,bus,name)

    def setUsermanProvider(self, provider):
        self.provider = provider

    @dbus.service.method(INTF_NAME, "", "")
    def test(self):
        print("TEST")

    @dbus.service.method(INTF_NAME, "", "x")
    def GroupDel (self, groupname):
        r = call (["delgroup", groupname])
        return r

class UserManUsers (dbus.service.Object):
    def __init__(self, bus, name):
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self,bus,name)

    def setUsermanProvider(self, provider):
        self.provider = provider

    @dbus.service.method(INTF_NAME, "", "")
    def test(self):
        print("TEST")

    @dbus.service.method(INTF_NAME, "ssss", "x")
    def UserAdd (self, gecos, username, groupname, passwd):
        if groupname:
            cmd = "adduser "  + " -g "  + gecos + " -G ", groupname + " " + username
        else:
            cmd = "adduser "  + " -g "  + gecos + username

        proc = pexpect.spawn (cmd)
        proc.expect ("[New password: ]")
        proc.sendline (passwd)
        proc.expect ("[Retype password: ]")
        proc.sendline (passwd)
        return 0


#        if groupname:
#            proc = subprocess.Popen(['adduser', "-g", gecos, "-G", groupname, username], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
#        else:
#            proc = subprocess.Popen(['adduser', "-g", gecos, username], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
#
#        with proc.stdout:
#            for prompt in iter(proc.stdout.readline, b''):
#                proc.stdin.write(passwd)
#
#        return 0

#        proc = subprocess.Popen(['passwd', username], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#        out,err = proc.communicate(passwd)
#        out,err = proc.communicate(passwd)
#        proc.stdin.write(passwd)
#        proc.stdin.write(passwd)
#        if (not err): return 0
#        print out
#        print err
#        return 0

    @dbus.service.method(INTF_NAME, "", "as")
    def UserList (self):
        userList = []
        with open("/etc/passwd", "r") as f:
            for usent in f:
                userParams = usent.split (":")
                if (int(userParams[2]) >= 1000 and int(userParams[2]) != 65534):
                    userList.append(userParams[0])
        return userList

class UserManUser (dbus.service.Object):
    def __init__(self, bus, name):
        self.bus = bus
        self.name = name
        dbus.service.Object.__init__(self,bus,name)

    @dbus.service.method(INTF_NAME, "", "")
    def test(self):
        print("TEST")

    def setUsermanProvider(self, provider):
        self.provider = provider

    @dbus.service.method(INTF_NAME, "s", "x")
    def UserDel (self, username):
        r = call (["deluser", username])
        return r

    @dbus.service.method(INTF_NAME, "ss", "x")
    def Passwd (self, username, passwd):
        r = call (["echo", "-e", passwd, "passwd", username])
        return r


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(DBUS_NAME, bus)

    Groupsobj   = UserManGroups (bus, OBJ_NAME_GROUPS)
    Groupobj    = UserManGroup  (bus, OBJ_NAME_GROUP)
    Usersobj    = UserManUsers  (bus, OBJ_NAME_USERS)
    Userobj     = UserManUser   (bus, OBJ_NAME_USER)

    Groupsobj.setUsermanProvider ("pam")
    Groupobj.setUsermanProvider ("pam")
    Usersobj.setUsermanProvider ("pam")
    Userobj.setUsermanProvider ("pam")

    mainloop = gobject.MainLoop()
    print("Started")
    mainloop.run()

if __name__ == '__main__':
    sys.exit(main())
