# Passerelle

Tunnel reverse HTTP(S) self-hosted. Équivalent personnel de ngrok / cloudflared.

```bash
passerelle open 8080
# https://a1b2c3d4.gnthr.dev → 127.0.0.1:8080
```

Voir [docs/architecture.md](docs/architecture.md) et [docs/adr/](docs/adr/).

## Build

Go 1.24+ :

```bash
make
# bin/passerelle
# bin/passerelle-gateway
```

## Usage rapide (local)

```bash
# Terminal 1 — gateway (certificat auto-généré en --dev)
./bin/passerelle-gateway run --dev --data-dir /tmp/passerelle-gw

# Terminal 2 — créer un user et un token
./bin/passerelle-gateway user add alice --data-dir /tmp/passerelle-gw
./bin/passerelle-gateway token create --user alice --data-dir /tmp/passerelle-gw

# Terminal 3 — client
./bin/passerelle enroll http://127.0.0.1:8080 --token <token> --insecure
./bin/passerelle open 3000
```

`--dev` écoute des ports non privilégiés, écrit un certificat auto-signé, et accepte le HTTP d’enrollment en clair sur localhost uniquement. Ce n’est pas un mode production.

## Production — gnthr.dev

Le wildcard **`*.gnthr.dev`** pointe déjà vers la machine gateway. Les tunnels sont donc `https://<aléatoire>.gnthr.dev`.

Un `*` ne couvre pas l’apex `gnthr.dev`. L’enrollment passe par **`passerelle.gnthr.dev`**, nom réservé (pas attribuable à un tunnel).

Certificat public (Let’s Encrypt DNS-01 via **Porkbun**) :

1. [porkbun.com/account/api](https://porkbun.com/account/api) — créer une paire API.
2. Domaine `gnthr.dev` → Details — activer l’accès API.
3. Sur cette machine :

```bash
brew install lego

ACME_EMAIL=toi@gnthr.dev \
PORKBUN_API_KEY=pk1_… \
PORKBUN_SECRET_API_KEY=sk1_… \
  ./packaging/issue-certs.sh
```

Puis, depuis cette machine (macOS), déployer par SSH :

```bash
./packaging/deploy-gateway.sh
# équivalent : make deploy-gateway
# autre hôte : ./packaging/deploy-gateway.sh root@passserelle.gnthr.dev
```

Le script compile `passerelle-gateway` pour Linux (amd64 ou arm64 selon le serveur), copie le binaire + unit systemd, crée l’utilisateur `passerelle`, et n’écrase pas un `gateway.toml` déjà présent.

Certificats optionnels au deploy :

```bash
DEPLOY_TLS_CERT=./tls.crt DEPLOY_TLS_KEY=./tls.key ./packaging/deploy-gateway.sh
```

Sans certs, le service est installé mais pas démarré. Avec certs, `systemctl restart passerelle-gateway`.

Ensuite sur le serveur (ou en SSH) :

```bash
ssh root@passerelle.gnthr.dev passerelle-gateway user add alice --data-dir /var/lib/passerelle
ssh root@passerelle.gnthr.dev passerelle-gateway token create --user alice --data-dir /var/lib/passerelle
```

Puis en local :

```bash
passerelle enroll https://passerelle.gnthr.dev --token psg_tok_…
passerelle open 8080
```

Pare-feu : UDP/443 (QUIC) et TCP/80+443. Le 80 ne fait que rediriger vers HTTPS.

## Install

Client macOS (ce dépôt est un tap Homebrew) :

```bash
brew tap gauthier/passerelle https://github.com/gauthier/passerelle
brew install passerelle
```

Puis :

```bash
passerelle enroll https://passerelle.gnthr.dev --token psg_tok_…
brew services start passerelle
passerelle open 8080
```

Gateway Ubuntu : [packaging/deploy-gateway.sh](packaging/deploy-gateway.sh) (SSH) ou [packaging/install-gateway.sh](packaging/install-gateway.sh) (déjà sur le serveur).
