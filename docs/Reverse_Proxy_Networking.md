# Reverse proxy and media networking

How to place a reverse proxy in front of Native KyMessages so the server sees each visitor's real
IP address, carries WebSocket chat/signaling traffic reliably, and optionally routes LiveKit SFU
media for larger group calls. Applies to `docker-compose.proxy.yml`.

## Why the proxy shares the app's network

Login and IP-keyed lockouts, plus audit log client addresses, depend on the direct peer address
being the real caller. Traffic that crosses between Docker networks or loops through a published
host port is source-NATed to a bridge gateway (`10.x.0.1`) shared by every visitor — causing one
attacker's failed logins to lock out everyone.

Instead, the reverse proxy joins `kymessages-net` and reaches the container by name
(`http://kymessages:8080`). Container-to-container traffic ignores published ports, and the proxy
overlay publishes none.

Each Ky app keeps its own Docker network (`kypost-net`, `kymessages-net`, etc.) so apps cannot
reach one another; only the reverse proxy joins multiple app networks.

## Setup

1. Append `docker-compose.proxy.yml` to `COMPOSE_FILE` in `.env`, keeping existing overlays
   (build, LAN-DNS, static-IP). Never replace the chain with `-f`.
2. Set `KY_APP_URL=https://<your host>`, `KY_SESSION_SECRET`, and
   `KY_TRUSTED_PROXIES=<proxy address>/32` (the proxy's pinned IP on `kymessages-net`).
   - Generate `KY_SESSION_SECRET` once with `openssl rand -hex 32` and keep it stable across
     restarts.
   - An `http://` `KY_APP_URL` is refused in production mode (`KY_ENV=production`).
   - `KY_TRUSTED_PROXIES` must list the proxy's exact `/32` address — never the subnet, which
     includes the Docker gateway and other containers that could then forge `X-Forwarded-For`.
3. Bring KyMessages up first so it creates and owns `kymessages-net` (`10.91.0.0/24` by default;
   override with `KY_NETWORK` / `KY_NETWORK_SUBNET`).

### With the static-IP overlay

`docker-compose.static-ip.yml` uses the same `KY_NETWORK_SUBNET`. Pin KyMessages and the proxy at
distinct addresses inside the subnet (for example, app at `10.91.0.20` and `cloudflared` or
`nginx` at `10.91.0.10`), and keep no unpinned containers on `kymessages-net`.

## cloudflared

Join an existing `cloudflared` container to `kymessages-net` as an external network:

```yaml
services:
  cloudflared:
    networks:
      kypost-net:
        ipv4_address: 10.89.0.10
      kymessages-net:
        ipv4_address: 10.91.0.10
networks:
  kypost-net:
    external: true
  kymessages-net:
    external: true
```

Route a single HTTPS hostname to KyMessages — the native server handles the web app, REST API,
WebSocket chat/signaling (`/api/v1/ws`), external guest meeting rooms (`/api/meet/{token}` and
`/api/meet/{token}/ws`), OIDC callbacks (`/api/sso/*`), directory sync webhooks, and operator
console (`/console`) all on port `8080`:

```yaml
ingress:
  - hostname: chat.example.com
    service: http://kymessages:8080
  - service: http_status:404
```

Set `KY_TRUSTED_PROXIES=10.91.0.10/32` and recreate KyMessages.

## nginx

Ensure WebSocket upgrades (`Upgrade` / `Connection`) and long read timeouts are enabled so
`/api/v1/ws` and `/api/meet/{token}/ws` stay connected, and set `client_max_body_size` at or above
`KY_MAX_UPLOAD_BYTES` (default 25 MiB) for chat attachments:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name chat.example.com;
    # ssl_certificate, ssl_certificate_key ...

    client_max_body_size 32m;

    location / {
        proxy_pass http://kymessages:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }
}
```

Run `nginx` on `kymessages-net` at a pinned IP and put that `/32` in `KY_TRUSTED_PROXIES`.

## Voice, video & optional LiveKit SFU

KyMessages supports two calling modes with zero extra subdomains required for basic P2P calls:

1. **Direct P2P WebRTC (default, zero extra services):**
   - Signaling runs over the existing `/api/v1/ws` (and `/api/meet/{token}/ws` for guests)
     WebSocket connection through your normal HTTPS reverse proxy.
   - Configure `KY_STUN_URLS` (comma-separated `stun:`/`stuns:` URIs) if you operate your own
     STUN server.
2. **Optional LiveKit SFU (`KY_LIVEKIT_URL`, `KY_LIVEKIT_API_KEY`, `KY_LIVEKIT_API_SECRET`):**
   - Enables multi-party SFU routing and automatic escalation from P2P calls.
   - Proxy LiveKit's signaling port (`http://livekit:7880`) over HTTPS/WSS on a dedicated hostname
     (e.g. `https://sfu.example.com`), blocking `/twirp/` externally (`return 404;`) so LiveKit's
     admin RPC API stays internal only:

     ```nginx
     server {
         listen 443 ssl;
         server_name sfu.example.com;
         # ssl_certificate, ssl_certificate_key ...
         location ^~ /twirp/ { return 404; }
         location / {
             proxy_pass http://livekit:7880;
             proxy_http_version 1.1;
             proxy_set_header Upgrade $http_upgrade;
             proxy_set_header Connection $connection_upgrade;
             proxy_read_timeout 1h;
         }
     }
     ```

   - Forward direct media ports (`TCP 7881` and `UDP 7882`) to the LiveKit host. HTTP tunnels such
     as `cloudflared` cannot carry WebRTC UDP media; restrictive client firewalls require an
     external TURN/TLS relay on TCP 443 / UDP 3478 with a DNS-only hostname and trusted
     certificate.

## Outbound Web Push connectivity

When Web Push is enabled (default; disable with `KY_PUSH_ENABLED=false`), the KyMessages server
opens outbound HTTPS connections (port 443) to browser push endpoints (FCM, Mozilla AutoPush,
Apple Web Push). Ensure your egress firewall allows outbound TCP 443 from the `kymessages`
container. The server validates every registered push endpoint against private/loopback IP ranges
to prevent SSRF.

## Verify

Sign in as an operator and open **Settings > Network path** (or `GET /api/installer/network`).
All five checks should report **Pass**:

- Request arrived through a trusted proxy (direct peer is in `KY_TRUSTED_PROXIES`)
- Proxy reports HTTPS (`X-Forwarded-Proto: https`)
- `KY_APP_URL` uses `https://`
- Request `Host` matches `KY_APP_URL`
- `KY_TRUSTED_PROXIES` names explicit `/32` addresses (not empty, not a broad subnet)

Your real client IP address — not the proxy's `10.91.0.x` IP — must be shown.

## Recovering Docker network conflicts

- `network kymessages-net declared as external, but could not be found`: start KyMessages first,
  then start the reverse proxy.
- `network kymessages-net was found but has incorrect label`: remove the manually created network
  so Compose can recreate it cleanly:

  ```sh
  docker compose down
  docker network inspect kymessages-net -f '{{range .Containers}}{{.Name}} {{end}}'
  docker network disconnect -f kymessages-net <container>
  docker network rm kymessages-net
  ```


## Gated hosted call affinity

`KY_TENANCY_MODE=multi` is still refused at startup. The following describes the runtime
contract for internal qualification, not an authorized hosted deployment or an alternative to
S3. Single-mode proxy configuration stays unchanged.

Route all `/api/v1/rooms/{room}/calls/…` requests by the **same room ID**, including member
state/join/leave/escalate/WebSocket and guest `calls/guest/{token}/…` paths. Hashing the whole
URL, cookie, guest token or client IP splits call control. Ordinary `/api/v1/ws` and
`/api/meet/{token}/ws` carry chat/lobby traffic and may reach any replica. Keep the same
eligible call replicas and consistent hash policy on every edge. One Nginx illustration:

```nginx
# http context; example backend names only, not a deployment manifest
map $uri $ky_call_room {
    ~^/api/v1/rooms/([^/]+)/calls/ $1;
    default "";
}
map $http_upgrade $ky_call_connection {
    default upgrade;
    "" close;
}
upstream ky_room_calls {
    hash $ky_call_room consistent;
    server messages-a:8080;
    server messages-b:8080;
}
# Inside the existing HTTPS server, retaining its trusted-proxy/TLS policy:
location ~ ^/api/v1/rooms/[^/]+/calls/ {
    proxy_pass http://ky_room_calls;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $ky_call_connection;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 75s;
}
```

The application authorizes the exact principal/org/room before claiming ownership. A request
on a competing replica returns 503 `call_owner_unavailable` with `Retry-After: 1`; it neither
redirects credentials to a pod address nor creates another call. Correct inconsistent edge
routing instead of retrying a different unverified host. After a dead owner stops renewing,
its lease expires within 90 seconds; a new owner retires old media before issuing fresh
credentials and clients rejoin through the same room route. Media can be interrupted.

Keep the eligible call pool stable while calls are active. For a topology change, drain and
stop removed owners' call processing before changing the eligible pool; a still-running old
owner would otherwise keep renewing its lease. Do not claim seamless rolling migration or
hosted capacity from this example. PostgreSQL/S3, isolation, browser/media, recovery and all
other launch gates remain required. Guest E2EE is not established by room affinity.
