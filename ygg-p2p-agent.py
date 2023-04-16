import logging
import socket
from time import sleep, monotonic
from threading import Thread
from sys import argv
import os
from typing import Optional

from yggdrasilctl import AdminAPI
import stun
from util import recv_msg, send_msg
from config import whitelist, listen_port, api_endpoint

## Globals ##
logger = logging.getLogger()
protocol_version = b'ygg-p2p-agent-tcp-v0.1'
# List of yggdrasil addresses of currently active outbound connections
sessions = {}
# List of yggdrasil addresses of currently opened bridges
bridges = {}
# Self external address
external_address = None # "{ip}:{port}"
# Yggdrasil AdminAPI
api = AdminAPI(address=api_endpoint)
# Local listen port
local_port = 0

# Create socket with same port as listen socket
def getsocket() -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.settimeout(4)
    sock.bind(('0.0.0.0', local_port))
    if local_port != 0 and sock.getsockname()[1] != local_port:
        raise Exception(f"getsocket(): Unnable to bind new socket to port {local_port}")
    logger.debug(f"New socket bound to {sock.getsockname()}")
    return sock

# Auxilary one-direction data pipe: (input socket) >-(bridge_relay)-> (output socket)
def bridge_relay(input: socket, output: socket) -> None:
    # Zero-copy implementaion using `splice(2)` syscall
    input_addr, output_addr = input.getsockname(), output.getpeername()
    input.setblocking(True)
    output.setblocking(True)
    input_fd = input.fileno()
    output_fd = output.fileno()
    o, i = os.pipe() # One of fds in every `splice(2)` call must be a pipe
    try:
        while True:
            l = os.splice(input_fd, i, 2**16)
            if l <= 0:
                break
            l = os.splice(o, output_fd, l, flags=os.SPLICE_F_NONBLOCK)
            if l <= 0:
                break
            logger.debug(f"Bridge relay {l} byte(s) from {input_addr} to {output_addr}")
    except Exception as err:
        logger.debug(f"Bridge failed from {input_addr} to {output_addr}: {err}")
    input.close()
    output.close()

# Try to establish bridge: (local yggdrasil node) <---> (temporary socket) <-(bridge_relay)-> (bridge_sock)
def bridge(bridge_sock: socket) -> None:
    peer_name = bridge_sock.getpeername()
    logger.debug(f"Trying to establish bridge with {peer_name}")

    # Create temporary socket
    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.settimeout(10)
    local_sock.bind(('0.0.0.0', 0))
    local_sock.listen(5)

    # Connect yggdrasil to temporary socket
    local_sock_addr = local_sock.getsockname()
    uri = f"tcp://{local_sock_addr[0]}:{local_sock_addr[1]}"
    logger.debug(f"addpeer uri: {uri} for {peer_name}")
    api.request('addpeer', uri=uri, interface='')

    ygg_sock = None
    try:
        ygg_sock, _ = local_sock.accept()
    except Exception as err:
        logger.debug(f"Failed to connect yggdrasil to the bridge: {uri}: {err}")
        return

    # Start bridging
    address = None
    try:
        logger.info(f"Bridging {ygg_sock.getsockname()} with {peer_name}")
        Thread(target=bridge_relay, args=(bridge_sock, ygg_sock)).start()
        Thread(target=bridge_relay, args=(ygg_sock, bridge_sock)).start()
        try:
            while True:
                sleep(60)
                if not uri in [ peer['remote'] for peer in api.request('getpeers')['peers'] ]:
                    raise Exception("Peer is not connected to the router")
                if bridge_sock.fileno() == -1:
                    raise Exception("P2P connection is closed")
                if ygg_sock.fileno() == -1:
                    raise Exception("Temporary socket is closed")
                if not address:
                    for peer in api.request('getpeers')['peers']:
                        if peer['remote'] == uri:
                            address = peer['address']
                            bridges[address] = ""
                if address:
                    if not address in [ session['address'] for session in api.request('getsessions')['sessions'] ]:
                        raise Exception("Session is closed")
        except Exception as err:
            logger.info(f"Closing bridge with {peer_name}: {err}")
        api.request('removepeer', uri=uri, interface='')
        sleep(5)
        bridge_sock.close()
        ygg_sock.close()
    finally:
        if address:
            bridges.pop(address)

# Try "handshake" (symmetric)
def handshake(peer: socket) -> None:
    try:
        peer_name = peer.getpeername()
        # Check remote agent protocol version
        send_msg(peer, protocol_version)
        msg = recv_msg(peer)
        logger.debug(f"Handshake: recv_msg from {peer.getpeername()}: {msg}")
        if msg != protocol_version:
            logger.debug(f"Handshake failed with {peer.getpeername()}: Invalid protocol version")
            return

        # Exchange external ips
        send_msg(peer, external_address.encode('ascii'))
        peer_address = recv_msg(peer).split(b':',1)
        peer_address = (peer_address[0].decode(), int(peer_address[1]))
        socket.inet_aton(peer_address[0])
        socket.htons(peer_address[1])
        peer.close()

        # Try NAT traversal
        logger.debug(f"Trying to create p2p bridge with {peer_address}")
        bridge_sock = getsocket()
        ok = False
        for _ in range(0, 20):
            try:
                bridge_sock.settimeout(1)
                bridge_sock.connect(peer_address)
                ok = True
                break
            except:
                sleep(0.5)
                continue
        if not ok:
            logger.debug(f"Failed to create p2p bridge with {peer_address}")
            return

        # Initiate bridge
        bridge(bridge_sock)
    except Exception as err:
        logger.debug(f"Handshake failed with {peer_name}: {err}")
        raise err
    finally:
        peer.close()

# Set up listen socket
def external_listener() -> None:
    global local_port
    sock = None
    while local_port == 0:
        try:
            sock = getsocket()
            sock.listen(10)
            local_port = sock.getsockname()[1]
        except Exception as err:
            logger.debug(f"Error while setting listening socket up: {err}")
            continue
    while local_port != 0:
        try:
            sock, _ = sock.accept()
            if external_address != None:
                Thread(target=bridge, args=(sock,)).start()
            else:
                sock.close()
        except TimeoutError:
            continue
        except Exception as err:
            logger.debug(f"Error while setting listening socket up: {err}")

# Try to connect to remote agent
def try_connect(sessions: dict, address: str) -> None:
    sessions[address] = ""
    try:
        logger.debug(f"Trying to connect to remote agent at {address}")
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(20)
        sock.connect((address, listen_port))
        logger.debug(f"Connected to remote agent at {address}")
        handshake(sock)
    except Exception as err:
        logger.debug(f"Failed to connect to remote agent at {address}: {err}")
    finally:
        sessions.pop(address)

# Set up listen socket in yggdrasil network
def yggdrasil_listener() -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(20)
    sock.bind(('::', listen_port))
    sock.listen(20)
    while sock:
        try:
            peer, address = sock.accept()
            logger.debug(f"Connection received from {address}")
            if external_address != None and (not whitelist or address[0] in whitelist):
                Thread(target=handshake, args=(peer,)).start()
            else:
                peer.close()
        except Exception as err:
            continue

# Resolve self external address via STUN
def resolve_external_address() -> None:
    global external_address
    while True:
        try:
            addr = stun.resolve(getsocket)
            if not addr:
                raise Exception("No STUN reached")
            external_address = f"{addr[0]}:{addr[1]}"
            break
        except Exception as err:
            logging.debug(f"Error while resloving stun: {err}")
            sleep(2)
    logger.debug(f"External address: {external_address}")

def main() -> int:
    # Set yggdrasil network listener up
    Thread(target=yggdrasil_listener).start()
    # Set NAT traversal socket up
    Thread(target=external_listener).start()
    while local_port == 0:
        sleep(1)
    try:
        # Main loop
        stun_watchdog = monotonic()
        while True:
            # Flush watchdog if there is active bridge
            if bridges != {}:
                stun_watchdog = monotonic()
            # Resolve external address if no bridge has been established for a long time
            if external_address == None or stun_watchdog < monotonic() - 40: # in seconds
                resolve_external_address()
                stun_watchdog = monotonic()
            # Spawn handler for new sessions
            for address in [ session['address'] for session in api.request('getsessions')['sessions'] ]:
                if (sessions.get(address) == None
                    and bridges.get(address) == None
                    and (not whitelist or address in whitelist)):
                    Thread(target=try_connect, args=(sessions, address)).start()
            sleep(10)
    except Exception as err:
        logging.error(err)
        return 1
    return 0

if __name__ == '__main__':
    logging.basicConfig(
        level=(logging.DEBUG if '--debug' in argv else logging.INFO),
        format='%(asctime)s - %(message)s')
    exit(main())
