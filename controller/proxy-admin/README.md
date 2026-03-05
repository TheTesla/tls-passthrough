# ProxyAdmin

FastAPI-Webanwendung zur Verwaltung von SNI-Domains, Backend-Routern und internen IP-Adressen (10.x.x.x) mit GitHub OAuth Login.

## Features

- **GitHub OAuth Login** – Nur autorisierte GitHub-Accounts erhalten Zugang
- **Nutzerverwaltung** – Admin-Rechte vergeben/entziehen, Nutzer de-/aktivieren
- **SNI-Domain-Verwaltung** – Domains anlegen, bearbeiten, Wildcard-Domains (*.example.com) unterstützt
- **Backend-Router** – Router mit Protokoll (http/https/tcp/udp) und Port konfigurieren
- **Interne IPs** – IP-Adressen im 10.x.x.x Bereich verwalten
- **Vollständige Datensynchronisation** – Alle Daten werden beim Laden einmalig komplett synchronisiert (`/api/sync`), Navigation erfordert kein Nachladen
- **Single-Page-App** – Keine Seitenreloads bei Navigation
- **Rollenbasiert** – Admins können alles, normale Nutzer können nur lesen

## Schnellstart

### 1. GitHub OAuth App erstellen

1. Gehe zu [GitHub → Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Klicke **New OAuth App**
3. Setze **Authorization callback URL**: `http://localhost:8000/auth/callback`
4. Notiere **Client ID** und **Client Secret**

### 2. Konfiguration

```bash
cp .env.example .env
```

`.env` anpassen:
```env
GITHUB_CLIENT_ID=dein_client_id
GITHUB_CLIENT_SECRET=dein_client_secret
GITHUB_REDIRECT_URI=http://localhost:8000/auth/callback
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USERS=dein_github_username
```

### 3. Starten

**Mit Docker Compose:**
```bash
docker compose up -d
```

**Lokal:**
```bash
pip install -r requirements.txt
python main.py
```

→ Öffne http://localhost:8000

## Projektstruktur

```
proxy-admin/
├── main.py                 # FastAPI-App, Routen
├── models/
│   ├── database.py         # SQLAlchemy-Modelle (User, SNIDomain, BackendRouter, InternalIP)
│   └── schemas.py          # Pydantic-Schemas + FullSync-Payload
├── routers/
│   ├── auth.py             # GitHub OAuth, Session-Management
│   └── api.py              # REST-API für alle Ressourcen
├── templates/
│   ├── login.html          # Login-Seite
│   └── app.html            # SPA (Single-Page-App)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## API-Endpunkte

| Methode | Pfad | Beschreibung |
|---------|------|--------------|
| GET | `/api/sync` | Alle Daten auf einmal (FullSync) |
| GET/POST | `/api/domains` | SNI-Domains |
| PUT/DELETE | `/api/domains/{id}` | Domain bearbeiten/löschen |
| GET/POST | `/api/routers` | Backend-Router |
| PUT/DELETE | `/api/routers/{id}` | Router bearbeiten/löschen |
| GET/POST | `/api/ips` | Interne IPs |
| PUT/DELETE | `/api/ips/{id}` | IP bearbeiten/löschen |
| GET | `/api/users` | Nutzerliste (Admin) |
| PUT/DELETE | `/api/users/{id}` | Nutzer verwalten (Admin) |

API-Dokumentation: http://localhost:8000/api/docs
