# Deploying Cipherwire on AWS EC2 with Caddy

This guide uses one Ubuntu EC2 instance. Caddy terminates TLS and reverse-proxies WebSockets to the relay on loopback. The relay port is never exposed to the internet.

Replace every placeholder:

- `<DOMAIN>` — e.g. `chat.example.com`
- `<AWS_REGION>` — e.g. `us-east-1`
- `<INSTANCE_TYPE>` — e.g. `t3.small`
- `<KEY_NAME>` — your EC2 SSH key pair
- `<ELASTIC_IP>` — the Elastic IP allocated for the instance
- `<ADMIN_CIDR>` — your administrator IP range, e.g. `203.0.113.10/32`

The instance size depends on expected concurrency; the relay is lightweight but RSA signature verification is CPU work. Start small and monitor.

## 1. EC2 and network

1. Launch an Ubuntu 24.04 LTS instance in `<AWS_REGION>` with type `<INSTANCE_TYPE>` and key pair `<KEY_NAME>`.
2. Allocate an Elastic IP and associate it with the instance. Point the DNS A record for `<DOMAIN>` at `<ELASTIC_IP>` (and AAAA if you use IPv6).
3. Security group inbound rules:
   - SSH (22) from `<ADMIN_CIDR>` only.
   - HTTP (80) from `0.0.0.0/0` and `::/0` for ACME and redirects.
   - HTTPS (443) from `0.0.0.0/0` and `::/0`.
   - **Do not open 55555.**
4. On the host:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git ufw curl
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 2. Install Caddy

Use Caddy's official Debian/Ubuntu repository:

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

Caddy obtains and renews the certificate automatically once DNS points at the instance and ports 80/443 are reachable.

## 3. Install the relay

```bash
sudo useradd --system --home /opt/cipherwire --shell /usr/sbin/nologin cipherwire
sudo mkdir -p /opt/cipherwire /etc/cipherwire
sudo chown cipherwire:cipherwire /opt/cipherwire

sudo -u cipherwire git clone https://github.com/SatyamBage/cipherwire.git /opt/cipherwire
sudo -u cipherwire python3 -m venv /opt/cipherwire/.venv
sudo -u cipherwire /opt/cipherwire/.venv/bin/pip install --upgrade pip
sudo -u cipherwire /opt/cipherwire/.venv/bin/pip install -r /opt/cipherwire/requirements.txt
```

Create the environment file:

```bash
sudo install -m 600 -o root -g root /opt/cipherwire/deploy/cipherwire.env.example /etc/cipherwire/cipherwire.env
sudoedit /etc/cipherwire/cipherwire.env
```

At minimum set:

```dotenv
CHAT_HOST=127.0.0.1
CHAT_PORT=55555
CHAT_STATE_DIR=/var/lib/cipherwire
CHAT_ALLOWED_ORIGINS=https://<DOMAIN>
```

The state directory contains the public-key registry and nicknames, not private keys. `StateDirectory=cipherwire` in the unit creates it with mode `0700`.

Install and start the service:

```bash
sudo install -m 644 /opt/cipherwire/deploy/cipherwire.service /etc/systemd/system/cipherwire.service
sudo systemctl daemon-reload
sudo systemctl enable --now cipherwire
sudo systemctl status cipherwire --no-pager
curl http://127.0.0.1:55555/healthz
```

The health response should be JSON with `"status":"ok"`.

## 4. Configure Caddy

```bash
sudo install -m 644 /opt/cipherwire/deploy/Caddyfile /etc/caddy/Caddyfile
printf 'CHAT_DOMAIN=%s\n' '<DOMAIN>' | sudo tee /etc/caddy/environment
sudo chmod 600 /etc/caddy/environment
sudo systemctl restart caddy
sudo systemctl status caddy --no-pager
```

If your Caddy package does not load `/etc/caddy/environment`, check `systemctl cat caddy` and add an `EnvironmentFile=` drop-in, or replace `{$CHAT_DOMAIN}` in the Caddyfile with the literal domain. Keep the Caddyfile outside the repository if you prefer not to use environment expansion.

Verify from your workstation:

```bash
curl -I https://<DOMAIN>/
curl https://<DOMAIN>/healthz
```

Open `https://<DOMAIN>/` and create a browser identity. The relay will allow the browser WebSocket because its origin is `https://<DOMAIN>`.

## 5. CLI access

On a client machine:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python setup_keys.py
CHAT_SERVER_URL=wss://<DOMAIN> python client.py
```

Compare both fingerprints with your contact through another channel before using `/trust`. The relay never needs the client private keys.

## 6. Separate static hosting

To serve `index.html`, `styles.css`, `app.js`, and `favicon.svg` from a static host:

1. Upload those four files, preserving relative paths.
2. Set `CHAT_ALLOWED_ORIGINS=https://<STATIC_HOST>` in `/etc/cipherwire/cipherwire.env` and restart the relay.
3. Open the static page, enter `wss://<DOMAIN>` as the relay URL, and connect.
4. Configure the static host to send at least:

```text
Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*; worker-src 'none'; manifest-src 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: DENY
```

Caddy still terminates TLS for the relay domain; the static host only serves the client files.

## 7. Operations

```bash
sudo journalctl -u cipherwire -f
sudo journalctl -u caddy -f
sudo systemctl restart cipherwire
```

Caddy writes access logs to `/var/log/caddy/cipherwire-access.log` by default in the provided Caddyfile. Those logs contain request metadata, not message plaintext. Treat them as sensitive and rotate/retain them accordingly.

Updates:

```bash
sudo -u cipherwire git -C /opt/cipherwire pull --ff-only
sudo -u cipherwire /opt/cipherwire/.venv/bin/pip install -r /opt/cipherwire/requirements.txt
sudo systemctl restart cipherwire
```

Back up `/var/lib/cipherwire/identities-v2.json` if you want to preserve public-key pins and nicknames. Back up client `.keys/` separately and securely; losing those private keys loses the identity. The relay state does not contain client private keys.

## 8. Hardening checklist

- [ ] Port 55555 is bound to `127.0.0.1` and blocked by the security group.
- [ ] SSH is restricted to `<ADMIN_CIDR>`.
- [ ] Only 80/443 are public.
- [ ] `CHAT_ALLOWED_ORIGINS` lists exact HTTPS origins; no wildcard.
- [ ] Caddy has a valid certificate and HTTP redirects to HTTPS.
- [ ] `/healthz` works over HTTPS.
- [ ] Systemd hardening is active (`systemd-analyze security cipherwire`).
- [ ] OS and Python dependencies are patched.
- [ ] Fingerprints are verified out of band before `/trust`.
- [ ] v1 is not deployed anywhere; old v1 hostnames are retired.
