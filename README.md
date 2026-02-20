# EU Captcha CrowdSec Bouncer

A standalone reverse proxy that connects [CrowdSec](https://www.crowdsec.net/) with [EU CAPTCHA](https://eu-captcha.eu) — a privacy-first, GDPR-compliant anti-bot solution hosted in Europe.

IPs that CrowdSec flags with a `captcha` decision are presented with the EU CAPTCHA widget before access is granted. IPs with a `ban` decision receive a 403. All other traffic is proxied transparently to your backend.

- **Dashboard:** [app.eu-captcha.eu](https://app.eu-captcha.eu)
- **Documentation:** [docs.eu-captcha.eu/integration/crowdsec](https://docs.eu-captcha.eu/integration/crowdsec/)

## How it works

```
Client → cs-eucaptcha-bouncer → Your application
              ↕
        CrowdSec LAPI
```

1. The bouncer polls CrowdSec's decision stream (`/v1/decisions/stream`) and keeps an in-memory cache.
2. On each request it looks up the client IP:
   - **ban** → 403 Forbidden
   - **captcha** → redirect to `/__captcha__`, serve EU CAPTCHA widget, verify token server-side, set HMAC-signed cookie, redirect back
   - **no decision** → proxy to upstream

## Requirements

- A running CrowdSec agent with an accessible Local API
- An EU CAPTCHA account with a sitekey and secret — [sign up at app.eu-captcha.eu](https://app.eu-captcha.eu)

## Installation

### Pre-built binary

Download the binary for your platform from the [releases page](https://github.com/Myra-Security-GmbH/eu-captcha-crowdsec/releases):

```sh
# Linux amd64
curl -L https://github.com/Myra-Security-GmbH/eu-captcha-crowdsec/releases/latest/download/cs-eucaptcha-bouncer-linux-amd64 \
  -o cs-eucaptcha-bouncer
chmod +x cs-eucaptcha-bouncer
```

Binaries are available for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64).

### Build from source

Go 1.22+ required.

```sh
git clone https://github.com/Myra-Security-GmbH/eu-captcha-crowdsec.git
cd eu-captcha-crowdsec
make build
# produces ./cs-eucaptcha-bouncer
```

## Quick start

**1. Register the bouncer with CrowdSec:**

```sh
cscli bouncers add eu-captcha-bouncer
# Note the printed API key — you'll need it in the next step
```

**2. Create your config:**

```sh
cp config.yaml.example config.yaml
```

Fill in the required values:

```yaml
listen_addr: "0.0.0.0:8080"
upstream_url: "http://localhost:3000"   # your application

crowdsec:
  lapi_url: "http://localhost:8080"
  api_key: "<API key from cscli bouncers add>"
  update_interval: "10s"

eu_captcha:
  sitekey: "<your sitekey>"    # from app.eu-captcha.eu
  secret:  "<your secret>"     # from app.eu-captcha.eu

session:
  secret: "<random hex string>"  # openssl rand -hex 32
  ttl: "1h"
```

**3. Run:**

```sh
./cs-eucaptcha-bouncer -config config.yaml
```

Point your load balancer or DNS at `listen_addr`. The bouncer logs to stdout in structured JSON.

## Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `0.0.0.0:8080` | Address to listen on |
| `upstream_url` | *(required)* | Backend to proxy to |
| `crowdsec.lapi_url` | `http://localhost:8080` | CrowdSec LAPI base URL |
| `crowdsec.api_key` | *(required)* | Bouncer API key from `cscli bouncers add` |
| `crowdsec.update_interval` | `10s` | Decision stream poll interval |
| `eu_captcha.sitekey` | *(required)* | EU CAPTCHA public sitekey |
| `eu_captcha.secret` | *(required)* | EU CAPTCHA private secret |
| `eu_captcha.verify_url` | `https://api.eu-captcha.eu/v1/verify` | Verification endpoint |
| `session.secret` | *(required)* | HMAC signing key (`openssl rand -hex 32`) |
| `session.cookie_name` | `__eucaptcha_pass` | Session cookie name |
| `session.ttl` | `1h` | How long a passed challenge remains valid |
| `trusted_proxies` | *(empty)* | CIDR ranges whose `X-Forwarded-For` is trusted |

## Deployment examples

### Systemd

```ini
[Unit]
Description=EU Captcha CrowdSec Bouncer
After=network.target crowdsec.service

[Service]
ExecStart=/usr/local/bin/cs-eucaptcha-bouncer -config /etc/eu-captcha-bouncer/config.yaml
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o cs-eucaptcha-bouncer ./cmd/cs-eucaptcha-bouncer

FROM alpine:3.19
COPY --from=builder /src/cs-eucaptcha-bouncer /usr/local/bin/
ENTRYPOINT ["cs-eucaptcha-bouncer", "-config", "/etc/bouncer/config.yaml"]
```

## Reserved paths

The bouncer uses two paths on the proxied domain. Do not use these in your application:

| Path | Purpose |
|------|---------|
| `/__captcha__` | Serves the EU CAPTCHA challenge page |
| `/__captcha__/verify` | Accepts the completed token |

## License

[Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/)
