# Passerelle

Tunnel reverse HTTP(S) self-hosted. Équivalent personnel de ngrok / cloudflared.

Tu héberges la gateway sur ton domaine ; le client, derrière NAT, expose un port local en HTTPS public.

```bash
passerelle auth https://passerelle.example.com
passerelle open 8080
# https://a1b2c3d4.example.com → 127.0.0.1:8080
```

Voir [docs/architecture.md](docs/architecture.md) et [docs/adr/](docs/adr/).

## Client

macOS, via le tap [gauthier/homebrew-tap](https://github.com/gauthier/homebrew-tap) :

```bash
brew tap gauthier/tap
brew install passerelle
```

Un opérateur de gateway te donne un token one-shot (il ne faut pas le coller sur la ligne de commande). Puis :

```bash
passerelle auth https://passerelle.example.com
# token:  (saisi masqué)
brew services start passerelle
passerelle open 8080
```

`auth` n’a pas de gateway par défaut : chaque instance a son URL. Le token se tape au prompt, sans écho.

## Gateway

Wildcard DNS `*.example.com` vers la machine. L’enrollment utilise un nom réservé, typiquement `passerelle.example.com` (un `*` ne couvre pas l’apex). Certificat TLS avec SAN `*.example.com`.

```bash
make
# bin/passerelle
# bin/passerelle-gateway
```

Déploiement SSH :

```bash
./packaging/deploy-gateway.sh root@gateway.example.com example.com
```

Certificats Let’s Encrypt (DNS-01, Porkbun par défaut) :

```bash
brew install lego

ACME_EMAIL=toi@example.com \
DOMAIN=example.com \
PORKBUN_API_KEY=pk1_… \
PORKBUN_SECRET_API_KEY=sk1_… \
  ./packaging/issue-certs.sh

DEPLOY_HOST=root@gateway.example.com \
BASE_DOMAIN=example.com \
DEPLOY_TLS_CERT=./certs/tls.crt DEPLOY_TLS_KEY=./certs/tls.key \
  ./packaging/deploy-gateway.sh
```

Le script écrit `base_domain` dans `/etc/passerelle/gateway.toml` (les autres clés déjà présentes sont conservées).

Sur le serveur :

```bash
passerelle-gateway user add alice --data-dir /var/lib/passerelle
passerelle-gateway token create --user alice --data-dir /var/lib/passerelle
passerelle-gateway user limits alice --data-dir /var/lib/passerelle
```

Pare-feu : UDP/443 (QUIC) et TCP/80+443. Le 80 ne fait que rediriger vers HTTPS.

Install sans SSH, déjà sur la machine : `./packaging/install-gateway.sh example.com`.

## Usage rapide (local)

```bash
# Terminal 1 — gateway (certificat auto-généré en --dev)
./bin/passerelle-gateway run --dev --data-dir /tmp/passerelle-gw

# Terminal 2 — user + token
./bin/passerelle-gateway user add alice --data-dir /tmp/passerelle-gw
./bin/passerelle-gateway token create --user alice --data-dir /tmp/passerelle-gw

# Terminal 3 — client
./bin/passerelle auth http://127.0.0.1:8080 --insecure
./bin/passerelle open 3000
```

`--dev` écoute des ports non privilégiés, écrit un certificat auto-signé, et accepte l’enrollment HTTP en clair sur localhost uniquement. Ce n’est pas un mode production.
