# Forked from `https://github.com/talkiq/pystun3`
# LICENCE: MIT
# Copyright (c) 2014-2018 pystun Developers
# Copyright (c) 2018 TalkIQ

from typing import Optional, Tuple, Callable
import binascii
import logging
import random
import socket
from config import stun_servers, stun_port

__version__ = '1.0.0'

log = logging.getLogger("pystun3")

# stun attributes
MappedAddress = '0001'
ResponseAddress = '0002'
ChangeRequest = '0003'
SourceAddress = '0004'
ChangedAddress = '0005'
Username = '0006'
Password = '0007'
MessageIntegrity = '0008'
ErrorCode = '0009'
UnknownAttribute = '000A'
ReflectedFrom = '000B'
XorOnly = '0021'
XorMappedAddress = '8020'
ServerName = '8022'
SecondaryAddress = '8050'  # Non standard extension

# types for a stun message
BindRequestMsg = '0001'
BindResponseMsg = '0101'
BindErrorResponseMsg = '0111'
SharedSecretRequestMsg = '0002'
SharedSecretResponseMsg = '0102'
SharedSecretErrorResponseMsg = '0112'

dictAttrToVal = {'MappedAddress': MappedAddress,
                 'ResponseAddress': ResponseAddress,
                 'ChangeRequest': ChangeRequest,
                 'SourceAddress': SourceAddress,
                 'ChangedAddress': ChangedAddress,
                 'Username': Username,
                 'Password': Password,
                 'MessageIntegrity': MessageIntegrity,
                 'ErrorCode': ErrorCode,
                 'UnknownAttribute': UnknownAttribute,
                 'ReflectedFrom': ReflectedFrom,
                 'XorOnly': XorOnly,
                 'XorMappedAddress': XorMappedAddress,
                 'ServerName': ServerName,
                 'SecondaryAddress': SecondaryAddress}

dictMsgTypeToVal = {
    'BindRequestMsg': BindRequestMsg,
    'BindResponseMsg': BindResponseMsg,
    'BindErrorResponseMsg': BindErrorResponseMsg,
    'SharedSecretRequestMsg': SharedSecretRequestMsg,
    'SharedSecretResponseMsg': SharedSecretResponseMsg,
    'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

dictValToMsgType = {}

dictValToAttr = {}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restric NAT"
RestricPortNAT = "Restric Port NAT"
SymmetricNAT = "Symmetric NAT"
ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"

def b2a_hexstr(abytes):
    return binascii.b2a_hex(abytes).decode("ascii")

def _initialize():
    global dictValToAttr, dictValToMsgType
    dictValToAttr= {v: k for k, v in dictAttrToVal.items()}
    dictValToMsgType = {v: k for k, v in dictMsgTypeToVal.items()}

def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
    # return binascii.a2b_hex(a)
    return a

def stun_test(sock, host, port, send_data=""):
    sock.connect((host, port))
    retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
              'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
              'ChangedPort': None}
    str_len = "%#04d" % (len(send_data) / 2)
    tranid = gen_tran_id()
    str_data = ''.join([BindRequestMsg, str_len, tranid, send_data])
    data = binascii.a2b_hex(str_data)
    recvCorr = False
    while not recvCorr:
        recieved = False
        count = 3
        while not recieved:
            log.debug(f"STUN send: {data}")
            try:
                sock.sendall(data)
            except socket.gaierror:
                retVal['Resp'] = False
                return retVal
            try:
                buf = sock.recv(2048)
                log.debug(f"STUN recv: {buf}")
                recieved = True
            except Exception:
                recieved = False
                if count > 0:
                    count -= 1
                else:
                    retVal['Resp'] = False
                    return retVal
        msgtype = b2a_hexstr(buf[0:2])
        bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
        tranid_match = tranid.upper() == b2a_hexstr(buf[4:20]).upper()
        if bind_resp_msg and tranid_match:
            recvCorr = True
            retVal['Resp'] = True
            len_message = int(b2a_hexstr(buf[2:4]), 16)
            len_remain = len_message
            base = 20
            while len_remain:
                attr_type = b2a_hexstr(buf[base:(base + 2)])
                attr_len = int(b2a_hexstr(buf[(base + 2):(base + 4)]), 16)
                if attr_type == MappedAddress:
                    port = int(b2a_hexstr(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(buf[base + 8:base + 9]), 16)),
                        str(int(b2a_hexstr(buf[base + 9:base + 10]), 16)),
                        str(int(b2a_hexstr(buf[base + 10:base + 11]), 16)),
                        str(int(b2a_hexstr(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ExternalIP'] = ip
                    retVal['ExternalPort'] = port
                if attr_type == SourceAddress:
                    port = int(b2a_hexstr(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(buf[base + 8:base + 9]), 16)),
                        str(int(b2a_hexstr(buf[base + 9:base + 10]), 16)),
                        str(int(b2a_hexstr(buf[base + 10:base + 11]), 16)),
                        str(int(b2a_hexstr(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['SourceIP'] = ip
                    retVal['SourcePort'] = port
                if attr_type == ChangedAddress:
                    port = int(b2a_hexstr(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(b2a_hexstr(buf[base + 8:base + 9]), 16)),
                        str(int(b2a_hexstr(buf[base + 9:base + 10]), 16)),
                        str(int(b2a_hexstr(buf[base + 10:base + 11]), 16)),
                        str(int(b2a_hexstr(buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ChangedIP'] = ip
                    retVal['ChangedPort'] = port
                # if attr_type == ServerName:
                    # serverName = buf[(base+4):(base+4+attr_len)]
                base = base + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
    # s.close()
    return retVal

def resolve(getsocket: Callable[[], socket.socket]) -> Optional[Tuple[str, int]]:
    _initialize()
    ret = None
    for stun_host in stun_servers:
        s = getsocket()
        try:
            log.debug('Trying STUN host: %s', stun_host)
            ret = stun_test(s, stun_host, port=stun_port)
            if ret['Resp']:
                break
        except Exception as err:
            log.debug(f"STUN Error: {err}")
        finally:
            s.close()

    return (ret['ExternalIP'], ret['ExternalPort']) if ret else None
