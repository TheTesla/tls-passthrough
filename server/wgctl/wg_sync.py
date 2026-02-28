#!/usr/bin/env python3

import os
import subprocess as sp
import tempfile
import redis


def run(cli, input=None):
    return sp.check_output(cli, input=input)

#def run_docker(cli, input=None, container_name="wireguard"):
#    return run(["docker", "exec", "-it", container_name] + cli)


def wg_syncconf(dev, data, run=run):
    with tempfile.NamedTemporaryFile(mode="w", delete=True) as f:
        f.write(data)
        f.flush()
        return run(["wg", "syncconf", dev, f.name])


def conf_dict2str(conf_dict):
    iface_dict = conf_dict["interface"]
    conf_str = f"""
[Interface]
ListenPort = {iface_dict["port"]}
PrivateKey = {iface_dict["privkey"]}
"""

    peers_list = conf_dict["peers"]
    conf_str += "".join([
        f"""
[Peer]
PublicKey = {peer["pubkey"]}
AllowedIPs = {",".join(peer["allowed_ips"])}
Endpoint = {peer["endpoint"]}
PersistentKeepalive = {peer["keepalive"]}
"""
        for peer in peers_list
    ])
    return conf_str


def load_config_from_env():
    return {
        "redis_host": os.environ.get("REDIS_HOST", "redis"),
        "redis_port": int(os.environ.get("REDIS_PORT", 6379)),
        "interface_port": int(os.environ.get("INTERFACE_PORT", 51820)),
        "endpoint": os.environ.get("WG_ENDPOINT", "127.0.0.1:51820"),
        "device": os.environ.get("WG_DEVICE", "wg0"),
        "privkey": os.environ["WG_PRIVATE_KEY"],  # absichtlich ohne Default
    }


def sync(c):
    conf = {}

    r = redis.Redis(
        host=c["redis_host"],
        port=c["redis_port"],
        decode_responses=True
    )

    peers_from_redis = r.hgetall("vpn:wg0:peers")

    peers_conf = [
        {
            "pubkey": k,
            "allowed_ips": [v],
            "endpoint": c["endpoint"],
            "keepalive": 24
        }
        for k, v in peers_from_redis.items()
    ]

    conf["interface"] = {
        "port": c["interface_port"],
        "privkey": c["privkey"]
    }

    conf["peers"] = peers_conf
    data = conf_dict2str(conf)

    wg_syncconf(c["device"], data)
    print(f"synched {len(peers_conf)} peers")


if __name__ == "__main__":
    config = load_config_from_env()
    sync(config)

