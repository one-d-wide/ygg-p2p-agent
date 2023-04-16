## Ygg-p2p-agent (proof-of-concept)
This project aims to transparently reduce latency of a connection over yggdrasil network for such applications as online gaming, VoIP and others.

## Work principle
The agent finds other agents over yggdrasil network. Exchanges external IP addresses with each other. Establishes peer-to-peer bridge using [NAT traversal](https://en.wikipedia.org/wiki/NAT_traversal) technique. And finally, adds this bridge as a peer to `yggdrasil-go` via [Admin API](https://yggdrasil-network.github.io/admin.html). Then traffic is being transparently rerouted through this minimal latency bridge with no need to reconnect or modify an application.

## What does it change
By default, `yggdrasil-go` routes packets through explicitly specified peers only. It does this [by design](https://github.com/yggdrasil-network/yggdrasil-go/issues/778#issuecomment-821802537). But, unless you try to connect to your direct peer or you do not have an internet connection at all, this is not the fastest route. The agent solves this issue by creating peer-to-peer bridge over internet and using it as a virtual peer endpoint, enabling `yggdrasil-go` to transparently reroute all traffic through the bridge.

## Usage
Dependencies: `python3`. Make sure `ygg-p2p-agent` can access [Admin API](https://yggdrasil-network.github.io/admin.html) socket.
```
$ git clone https://github.com/one-d-wide/ygg-p2p-agent
$ cd ygg-p2p-agent
$ # You can tweak some options in `./config.py`
$ python3 ygg-p2p-agent.py # --debug
```
The agent listens for incoming TCPv6 connections on port `9999`, hence it must be opened for peers you want to bridge with. Example shows temporarily opening ports for linux distributions using `iptables`:
```
# # Allow all connections to the port
# ip6tables -A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT
# # Allow connection only from <peer_address> to the port
# ip6tables -A INPUT -s <peer_address> -p tcp -m tcp --dport 9999 -j ACCEPT
```

## Drawbacks
- This routing scheme goes against yggdrasil's core self-structure assumptions (for example, it does not represent shortest route). This issue can be addressed by hiding this bridge (prohibiting of routing traffic of other nodes through it).
- Since such a scheme is not accounted for in the router implementation, bridge instantiation can take substantial amount of time.

## Implementation Details
 **Note that current implementation is a proof-of-concept, it is not resource efficient, has awful code style and lots of bugs.**

<details>
<summary>Peering Process</summary>

- Create and bind a socket in the Yggdrasil network.
- Create and bind a socket in the internet (for NAT traversal).
- Loop:
  - Obtain self external IP address via [STUN](https://en.wikipedia.org/wiki/STUN). Repeat if no bridge has been established in a long time.
  - Get active yggdrasil sessions (peers we have active packet exchange with) via [Admin API](https://yggdrasil-network.github.io/admin.html).
  - Try to connect to remote agent for each session.
  - (If successful) "Handshake" and exchange external IPs.
  - Try to establish P2P connection with remote peer.
  - (If successful) Create and bind bridging socket.
  - Add this socket as a yggdrasil peer.
  - Proxy all traffic between P2P and yggdrasil sockets until session is disconnected.
</details>

<details>
<summary>Establishing P2P Connection</summary>

Note that theoretical background of TCP hole-punching is out-of-scope of this project, and well-explained in [this paper](https://bford.info/pub/net/p2pnat).

- Bootstrap phase:
  - Create and bind listen and connection sockets to the same port (using `SO_REUSEADDR` and `SO_REUSPORT` flags), because UNIX TCP interface requires fresh socket for every new connection.
  - Obtain self external IP address via [STUN](https://en.wikipedia.org/wiki/STUN).
- Handshake phase:
  - Exchange external IP address and port with the peer.
  - Try to connect to the peer and listen for connection simultaneously.
</details>
