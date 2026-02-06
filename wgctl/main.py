#!/usr/bin/env python3


import subprocess as sp
import tempfile



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


data = conf_dict2str(conf)


print(wg_syncconf("wg0", data))

