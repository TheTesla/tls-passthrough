# TLS passthrough for NAT traversal

## Usage

```bash
docker compose up
docker exec -it sni-redis redis-cli set sni:test.example 10.200.0.2:443
```

## Test

To test on local machine

```bash
docker compose up
docker exec -it sni-redis redis-cli set sni:test.example 10.200.0.2:8443
```

`/etc/wireguard/wg0.conf`:

```
[Interface]
Address = 10.200.0.2/24
PrivateKey = eEc9VXVYwIiCjnKU3iPKud4Iv3G0BJI/cidoHAlRyV8=

[Peer]
PublicKey = 5834NbTrZiSHAk2ti8aYTm/9nCaZ+qJ43dMtLjL9tyk= 
AllowedIPs = 10.200.0.0/24, 172.42.0.2/32
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
```

Webserver must host TLScontent on port `8443` to prevent post conflict.


## License

AGPL v3

 
