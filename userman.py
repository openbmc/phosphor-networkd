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
        Interface:Method > org.openbmc.Enrol.GroupListUsr
        Interface:Method > org.openbmc.Enrol.GroupListSys
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
        if not groupname : raise ValueError("Invalid Groupname")

        groups = self.GroupListAll ()
        if groupname in groups: raise ValueError("Group ", groupname, " Exists")

        r = call (["addgroup", groupname])
        return r

    #@dbus.service.method(INTF_NAME, "s", "x")
    def GroupAddSys (self, groupname):
        if not groupname : raise ValueError("Invalid Groupname")

        groups = self.GroupListAll ()
        if groupname in groups: raise ValueError("Group ", groupname, " Exists")

        r = call (["addgroup", "-S", groupname])
        return r

    @dbus.service.method(INTF_NAME, "", "as")
    def GroupListUsr (self):
        groupList = []
        with open("/etc/group", "r") as f:
            for grent in f:
                groupParams = grent.split (":")
                if (int(groupParams[2]) >= 1000 and int(groupParams[2]) != 65534):
                    groupList.append(groupParams[0])
        return groupList

    @dbus.service.method(INTF_NAME, "", "as")
    def GroupListSys (self):
        groupList = []
        with open("/etc/group", "r") as f:
            for grent in f:
                groupParams = grent.split (":")
                if (int(groupParams[2]) > 100 and int(groupParams[2]) < 1000): groupList.append(groupParams[0])
        return groupList

    def GroupListAll (self):
        groupList = []
        with open("/etc/group", "r") as f:
            for grent in f:
                groupParams = grent.split (":")
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
        if not groupname : raise ValueError("Invalid Groupname")

        groups = Groupsobj.GroupListAll ()
        if groupname not in groups: raise ValueError("No such Group: ", groupname)

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
        if not username : raise ValueError("Invalid Username")

        users = self.UserListAll ()
        if username in users : raise ValueError("User ", username, " Exists")

        if groupname:
            groups = Groupsobj.GroupListAll ()
            if groupname not in groups: raise ValueError("No such Group: ", groupname)

        opts = ""
        if gecos: opts = " -g " + '"' + gecos + '"'

        if groupname:
            cmd = "adduser "  + opts + " " + " -G " + groupname + " " + "-s /bin/sh" + " " + username
        else:
            cmd = "adduser "  + opts + " " + "-s /bin/sh" + " " + username

        prompts = ['New password: ', 'Retype password: ', 'Re-enter new password: ']
        proc = pexpect.spawn (cmd)
        proc.expect (prompts)
        proc.sendline (passwd)
        proc.expect (prompts)
        proc.sendline (passwd)

        if proc.expect(prompts + [pexpect.EOF]) != len(prompts):
            proc.sendline (passwd)

        r = proc.wait()
        return r if r else 0

    @dbus.service.method(INTF_NAME, "", "as")
    def UserList (self):
        userList = []
        with open("/etc/passwd", "r") as f:
            for usent in f:
                userParams = usent.split (":")
                if (int(userParams[2]) >= 1000 and int(userParams[2]) != 65534):
                    userList.append(userParams[0])
        return userList

    def UserListAll (self):
        userList = []
        with open("/etc/passwd", "r") as f:
            for usent in f:
                userParams = usent.split (":")
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
        if not username : raise ValueError("Invalid Username")

        users = Usersobj.UserList ()
        if username not in users : raise ValueError("No such User: ", username)

        r = call (["deluser", username])
        return r

    @dbus.service.method(INTF_NAME, "ss", "x")
    def Passwd (self, username, passwd):
        if not username : raise ValueError("Invalid Username")

        users = Usersobj.UserList ()
        if username not in users : raise ValueError("No such User: ", username)

        cmd = "passwd" + " " + username
        prompts = ['New password: ', 'Retype password: ', 'Re-enter new password: ']
        proc = pexpect.spawn (cmd)
        proc.expect (prompts)
        proc.sendline (passwd)
        proc.expect (prompts)
        proc.sendline (passwd)

        if proc.expect(prompts + [pexpect.EOF]) != len(prompts):
            proc.sendline (passwd)

        r = proc.wait()
        return r if r else 0

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(DBUS_NAME, bus)

    global Groupsobj
    global Groupobj
    global Usersobj
    global Userobj

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

