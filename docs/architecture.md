# Architecture Passerelle

Passerelle est un tunnel reverse HTTP(S) self-hosted. Un client, derrière NAT, établit une connexion sortante chiffrée vers une gateway publique. La gateway termine le TLS des visiteurs et multiplexe chaque requête HTTP vers le service local demandé — et uniquement celui-là.

v1 transporte exclusivement du HTTP(S) (y compris WebSocket, SSE, streaming et uploads). Un tunnel TCP brut (SSH, Postgres, etc.) exigerait une nouvelle version de protocole (`passerelle/2`) ; ce n’est pas un champ mort dans `passerelle/1`.

## Composants

| Binaire | Rôle |
|---|---|
| `passerelle` | CLI, TUI et daemon utilisateur. Un seul binaire client. |
| `passerelle-gateway` | Listener public HTTPS, listener tunnel (QUIC / HTTP/2), enrollment, identité, routage. |

Le daemon est le seul processus qui détient la connexion tunnel et qui diale l’origine. La CLI et la TUI sont des clients d’une API HTTP locale (socket Unix / named pipe). Fermer le terminal ou la TUI ne ferme pas les tunnels.

```
Internet
   │  HTTPS (TCP 443)
   ▼
Passerelle Gateway
   │  tunnel chiffré persistant (QUIC UDP 443, repli HTTP/2 TCP 443, ALPN passerelle/1)
   ▼
Passerelle Client daemon
   │
   ▼
127.0.0.1:8080
```

## Flux réseau

```
Navigateur --TCP/443 HTTPS--> Public listener --Host--> Router
                                                          |
Client daemon --UDP/443 QUIC mTLS----------------------> Tunnel listener
Client daemon --TCP/443 ALPN passerelle/1--------------> Tunnel listener
                                                          |
                     Router --stream par requête HTTP--> Client daemon --TCP--> 127.0.0.1:port
```

- **Public** : HTTP/1.1 et HTTP/2 sur TCP. HTTP/3 public hors v1. Le port 80 ne fait que rediriger vers HTTPS.
- **Tunnel primaire** : QUIC (TLS 1.3) sur UDP, même port que le HTTPS public (443 en production). Les deux ne se marchent pas dessus (UDP vs TCP).
- **Repli** : TLS 1.3 + HTTP/2 sur TCP/443, ALPN `passerelle/1`. Nécessaire : l’UDP est souvent filtré.
- **Pas de nouvelle connexion tunnel par requête.** Une session multiplexée, un stream bidirectionnel par requête publique.
- **Enrollment** : `POST /v1/enroll` sur le listener HTTPS public, sans certificat client.

Le port 443 est volontaire. Cloudflared utilise 7844 ; pour un outil self-hosted, le 443 sort des réseaux d’entreprise et des Wi‑Fi publics. Les ports sont configurables (8443 en local, sans root).

## Modèle de sécurité

### Ce que Passerelle refuse

- Protocole cryptographique maison, WireGuard (VPN : trop large), SSH comme transport.
- TLS &lt; 1.3, 0-RTT QUIC (rejeu).
- Confiance dans un hostname, un `user_id` ou un `client_id` fourni par le client dans le protocole applicatif.
- Dial de l’origine vers autre chose que le loopback, sauf `--host` explicite et allowlist.
- Tunnels persistants après reboot, sauf `--persist`.
- Credentials, PEM, tokens dans les logs.

### Identité

Deux identités distinctes :

- `user_id` : une personne (opérateur, famille, ami). Porte les quotas et les sous-domaines réservés.
- `client_id` : une machine de cette personne. Porte le certificat mTLS.

Pas de mot de passe, pas d’OAuth, pas de dashboard web en v1. L’opérateur administre par CLI sur le serveur.

1. La gateway génère une **CA tunnel** interne (clé 0600, data dir).
2. `passerelle-gateway user add alice` crée l’utilisateur et ses quotas.
3. `passerelle-gateway token create --user alice` émet un bootstrap token one-shot, TTL court, hashé at rest, **lié au `user_id`**.
4. `passerelle auth <gateway-url>` : le client génère une clé, envoie une CSR. Le token se saisit au prompt (jamais en argument).
5. La gateway consomme le token, vérifie le quota devices, émet un certificat dont les URI SAN portent `user_id` et `client_id`.
6. Connexions tunnel suivantes : **mTLS**. L’identité est le certificat. Un hello protobuf qui prétend être bob est ignoré.
7. Clé privée device : Keychain / Credential Manager / libsecret ; fallback fichier 0600, loggué comme dégradé.

Isolation : Alice n’atteint pas les tunnels de Bob. Un stream n’est ouvert que vers un device du user propriétaire du hostname. Les sous-domaines réservés sont uniques **globalement** sur le domaine.

Révocation : `user revoke` (tous les certs) ou `device revoke` (un serial). Denylist persistée.

### Secrets

- Token d’enrollment : entropy cryptographique, hash SHA-256 stocké, valeur claire jamais loguée.
- Clé CA et clé gateway : fichiers 0600.
- Clé client : secret store OS.

## Modèle de connexion

Après enrollment, le daemon :

1. Dial QUIC vers `gateway:443` avec mTLS, ALPN `passerelle/1`, **sans** 0-RTT.
2. Si échec handshake UDP : repli HTTP/2/TLS sur TCP, même ALPN.
3. Ouvre un **stream de contrôle** (premier stream client).
4. Échange `Hello` / `HelloAck` (versions, pas d’identité — l’identité est déjà dans le cert).
5. Keepalive périodique sur le contrôle.
6. Pour chaque `open`, envoie `OpenTunnel` ; la gateway alloue un hostname et répond `OpenTunnelAck` avec l’URL publique.
7. Pour chaque requête publique, la gateway ouvre un **stream de données**, écrit un préambule `{tunnel_id}` puis la requête HTTP/1.1 ; le client diale `127.0.0.1:port` et pipe avec `io.Copy`.

Backpressure : flow control QUIC / HTTP/2 + flush immédiat. Aucun `ReadAll` du body. Pas de `MaxBytes` sur le body si on streame ; les limites portent sur le nombre de connexions, la taille des headers, les timeouts.

WebSocket : si l’origine répond `101`, le daemon et la gateway hijackent et copient les deux sens jusqu’à EOF.

## Lifecycle d’un tunnel

```
enroll/auth → daemon connecté → open → hostname alloué → requêtes multiplexées
                │                      │
                │                      ├─ close → hostname libéré (sauf persist / grâce)
                │                      └─ disconnect → grâce d’allocation (TTL)
                └─ reconnect (backoff+jitter) → ré-annonce des tunnels ouverts
```

- `passerelle open 8080` : éphémère. Survivt à la fermeture du terminal (daemon). **Ne** survit **pas** au reboot.
- `passerelle open 443 --https` : l’origine locale est HTTPS (TLS jusqu’à Docker/Apache). Le visiteur reste en HTTPS sur la gateway ; le dernier hop n’est plus du HTTP clair.
- `passerelle open 8080 --persist` : ré-ouvert au démarrage du daemon.
- `passerelle open 8080 --subdomain demo` : demande ; la gateway autorise (collision, appartenance, quotas). Refus = erreur, jamais d’override silencieux.
- Cible par défaut : `127.0.0.1`, pas `localhost` (IPv6 / `/etc/hosts`).
- Après sleep/wake ou changement d’IP : migration QUIC si la session vit ; sinon reconnect et ré-annonce. La gateway conserve le hostname pendant un TTL de grâce pour ne pas casser l’URL.
- Redémarrage gateway : l’état d’allocation durable est sur disque ; l’état mémoire des sessions se reconstruit à la reconnexion.

## Daemon / CLI / TUI

```
CLI / TUI  --HTTP sur UDS ou named pipe (0600, même uid)-->  daemon  --mTLS-->  gateway
launchd agent / systemd --user / tâche de session Windows --> daemon
```

- IPC : HTTP local, débogable (`curl --unix-socket`). gRPC rejeté (surkill). Authz = credentials du pair (SO_PEERCRED / équivalent Windows).
- Si le daemon n’écoute pas, la CLI tente de le démarrer via le service OS ; à défaut, message d’install (`passerelle service install`). Un mode `passerelle daemon` foreground existe pour le debug.
- TUI : abonnée à un flux d’événements (SSE) du daemon. Ce n’est pas un tail de logs.
- Scripts : `passerelle status --json`, `passerelle list --json`. Pas de TUI si stdout n’est pas un TTY, sauf `passerelle tui`.

CLI client (évolutive) :

```
passerelle auth <gateway-url>
passerelle open [host:]<port> [--subdomain] [--persist] [--https]
passerelle close [id|url|host|port] [--all]
passerelle list
passerelle status
passerelle tui
passerelle daemon
passerelle service install|uninstall|start|stop
```

CLI gateway :

```
passerelle-gateway run --config …
passerelle-gateway user add|list|revoke|limits <name>
passerelle-gateway token create --user <name>
passerelle-gateway device list|revoke
```

Pas de dashboard web en v1.

## Protocole client ↔ gateway

Isolé dans `protocol/`, versionné par ALPN `passerelle/1`.

Messages de contrôle : protobuf, préfixe longueur uint32 big-endian.

| Message | Sens | Rôle |
|---|---|---|
| `Hello` | C→G | versions client, pas d’identité |
| `HelloAck` | G→C | version négociée |
| `OpenTunnel` | C→G | subdomain demandé (optionnel), persist |
| `OpenTunnelAck` | G→C | `tunnel_id`, hostname, URL publique |
| `CloseTunnel` / `Ack` | C↔G | fermeture |
| `KeepAlive` | C↔G | RTT + liveness |
| `Error` | G→C | code machine + message |

Streams de données : préambule protobuf `{ tunnel_id }` puis HTTP/1.1 brut.

La gateway ignore toute identité déclarée dans `Hello`. Le routage public ignore le SNI/Host **envoyé par le client tunnel** : seul le `Host` du visiteur, croisé avec le registre serveur, compte.

## Routage public et TLS

- DNS de production (**gnthr.dev**) : le wildcard `*.gnthr.dev` pointe déjà vers la gateway. Les tunnels sont `https://<aléatoire>.gnthr.dev`. L’enrollment utilise `https://passerelle.gnthr.dev` (`passerelle` est un sous-domaine réservé). Un wildcard ne couvre pas l’apex `gnthr.dev`.
- MVP TLS public : certificat wildcard **en fichiers**. ACME DNS-01 (certmagic) est optionnel, désactivé par défaut.
- URL par défaut : `https://<aléatoire>.<base_domain>` (imprévisible).
- Hébergement non figé : ports, domaine et chemins de certs sont de la config, pas du code.
- Multi-gateway futur : l’interface `TunnelRegistry` masque le stockage (mémoire + fichier aujourd’hui ; Redis/etc. plus tard). Une session client reste collée à **une** gateway.

## Observabilité et limites

- Logs `log/slog` : texte côté client, JSON recommandé sur la gateway. Redaction des clés sensibles.
- Métriques Prometheus sur une bind **localhost** (jamais anonyme sur 0.0.0.0).
- Quotas par `user_id` : max devices, max tunnels, max connexions HTTP publiques concurrentes.
- Timeouts handshake, idle, headers ; rate limit `/v1/enroll` ; slowloris ; `MaxHeaderBytes`.

## Découpage du code

```
cmd/passerelle/              CLI + TUI + entrée daemon
cmd/passerelle-gateway/      CLI gateway
client/                      daemon, IPC, reconnect, keyring, origine
gateway/                     assemblage
gateway/public/              HTTPS public + redirect 80
gateway/tunnel/              QUIC + HTTP/2, sessions
gateway/router/              hostname → session
gateway/identity/            CA, users, tokens, devices, révocation
protocol/                    ALPN, proto, framing
internal/                    logging, limits, tlsutil
packaging/                   brew, systemd, launchd, install.sh
docs/
```

## Hors v1

- Tunnel TCP/UDP brut.
- HTTP/3 côté visiteur.
- Dashboard web, OAuth, billing.
- Mesh multi-gateway et anycast.
- Homebrew/Linuxbrew comme canal d’install **serveur** (le client macOS, oui ; Ubuntu = binaire + systemd).
