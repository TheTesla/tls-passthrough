#!/usr/bin/env python3


import subprocess as sp
import tempfile
import redis


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


def sync(c, privkey):
    conf = {}
    r = redis.Redis(host=c["redis_host"], port=c["redis_port"], decode_responses=True)
    peers_from_redis = r.hgetall("vpn:wg0:peers")
    peers_conf = [{"pubkey": k, "allowed_ips": [v], "endpoint": c["endpoint"], "keepalive": 24} for k, v in peers_from_redis.items()]
    conf["interface"] = {"port": c["redis_port"], "privkey": privkey}
    conf["peers"] = peers_conf
    data = conf_dict2str(conf)
    print(wg_syncconf("wg0", data))


if __name__ == "__main__":
    privkey = "eEc9VXVYwIiCjnKU3iPKud4Iv3G0BJI/cidoHAlRyV8="
    config = {"redis_host": "172.25.0.2", \
              "redis_port": 6379, \
              "interface_port": 38661, \
              "endpoint": "127.0.0.1:51820"}
    sync(config, privkey)


