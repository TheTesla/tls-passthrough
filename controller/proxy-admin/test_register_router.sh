# Pairing-Code des Routers (aufgedruckt)
CODE="A5GN-YMQ5"
PUBKEYA="GAyQATIk5pLdBPYDJ61atXEGVltUbGmkrEC15Sx5izM="
PUBKEYB="xuGLFMTf8xSr18PBzGZT4JvQngiBnIFkwjvhIpFbzEw="

# router_id berechnen (wie der Router es tut)
ROUTER_ID=$(python3 -c "
import hmac, hashlib, re, os
secret = os.getenv('ROUTER_ID_SECRET', 'dev-secret-change-in-production')
code = re.sub(r'[^A-Z2-9]', '', '$CODE'.upper())
print(hmac.new(secret.encode(), code.encode(), hashlib.sha256).hexdigest()[:32])
")
echo "Router-ID: $ROUTER_ID"

curl -s http://localhost:8000/api/router/$ROUTER_ID \
  -H "Authorization: Bearer $CODE" \
  -H "X-Hostname: test-router-1" \
  -H "X-Version: 1.0.0" #| python3 -m json.tool



curl -s http://localhost:8000/api/router/$ROUTER_ID \
  -H "Authorization: Bearer $CODE" \
  -H "X-WG-Public-Key: $PUBKEYB" \
  -H "X-Hostname: test-router-1" #| python3 -m json.tool

