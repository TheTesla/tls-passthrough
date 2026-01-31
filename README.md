# TLS passthrough for NAT traversal

## Usage

```bash
docker compose up
docker exec -it sni-redis redis-cli set sni:test.example 10.200.0.2:443
```

## License

AGPL v3

 
