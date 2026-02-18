#!/usr/bin/env python3


import subprocess as sp
import tempfile
import redis

r = redis.Redis(host="172.25.0.2", port=6379, decode_responses=True)

peers_from_redis = r.hgetall("vpn:wg0:peers")

def run(cli, input=None):
    return sp.check_output(cli, input=input)

def wg_syncconf(dev, data, run=run):
    with tempfile.NamedTemporaryFile(mode="w", delete=True) as f:
        f.write(data)
        f.flush()
        return run(['wg', 'syncconf', dev, f.name])

def conf_dict2str(conf_dict):
    iface_dict = conf_dict["interface"]
    conf_str = \
        f"""
        [Interface]
        ListenPort = {iface_dict["port"]}
        PrivateKey = {iface_dict["privkey"]}
        """
    peers_list = conf_dict["peers"]
    conf_str += "".join([ \
        f"""
        [Peer]
        PublicKey = {peer["pubkey"]}
        AllowedIPs = {",".join(peer["allowed_ips"])}
        Endpoint = {peer["endpoint"]}
        PersistentKeepalive = {peer["keepalive"]}
        """ for peer in peers_list])
    return conf_str

conf = {"interface": \
           {"port": 38661, \
            "privkey": "eEc9VXVYwIiCjnKU3iPKud4Iv3G0BJI/cidoHAlRyV8="}, \
        "peers": [ \
           {"pubkey": "5834NbTrZiSHAk2ti8aYTm/9nCaZ+qJ43dMtLjL9tyk=", \
            "allowed_ips": ["10.200.0.0/24", "172.42.0.2/32"], \
            "endpoint": "127.0.0.1:51820", \
            "keepalive": 24}]}

peers_conf = [{"pubkey": k, "allowed_ips": [v], "endpoint": "127.0.0.1:51820", "keepalive": 24} for k, v in peers_from_redis.items()]

conf["peers"] = peers_conf

data = conf_dict2str(conf)

print(data)

print(wg_syncconf("wg0", data))

