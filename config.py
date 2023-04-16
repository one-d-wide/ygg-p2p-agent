# Path to yggdrasil AdminAPI (UNIX socket)
api_endpoint = "/var/run/yggdrasil/yggdrasil.sock"

# Listen/connect port in yggdrasil network
listen_port = 9999

# Allowed yggdrasil network addresses
# Check is skipped if empty
whitelist = [
    # "<full yggdrasil ipv6 address>",
]

# STUN servers (must support TCP)
stun_servers = [
    "stunserver.stunprotocol.org",
]

# Default STUN port
stun_port = 3478