# Project Kronos - "Titan's Fall"

## Challenge Info

| Field | Value |
|---|---|
| **Title** | Titan's Fall |
| **Category** | Web / API Exploitation |
| **Difficulty** | Medium |
| **Flag** | `AdwaCTF{kr0n0s_4lg_n0ne_bypass_m4st3r}` |

## Description

> Our internal analytics service, Titan, sits on top of 17 trillion rows of telemetry data. Security says there's nothing to worry about — the frontend dashboard is strictly locked behind the employee VPN, and our API tokens verify every single organizational claim before granting access.
>
> See if you can prove them wrong and query the core database. Sometimes the hardest doors to open have the simplest keys.

## Deployment

### Docker Compose (Recommended)

```bash
docker-compose up --build
```

The challenge will be available at `http://localhost:5000`.

### Custom Flag

Set the `FLAG` environment variable:

```bash
FLAG="CTF{your_custom_flag_here}" docker-compose up --build
```

## Intended Solution Path

1. **Frontend Lockout**: Visit `/` — the login page always rejects with "Corporate VPN Subnet Required"
2. **Exposed Swagger Docs**: Discover `/swagger.json` or `/api/docs` — lists the API endpoints
3. **Information Disclosure**: Check `/robots.txt` — comments leak the path `/backup/superset_config_2023.bak`
4. **Leaked Config**: Download the backup config — contains JWT claim values (`tid`, `aud`, `appid`), reveals `jwt_sig_verify = false` and `alg: none` is accepted
5. **JWT alg:none Bypass**: Forge a JWT with `{"alg": "none", "typ": "JWT"}` header and the leaked claim values. Use `upn: "admin"` (not email format) to get Admin role
6. **Query the Flag**: Use `/v2/Query` with `routingTarget: "CoreAnalytics"` and `query: "SELECT * FROM flag_vault"` to extract the flag

## Solve Script

```bash
pip install requests
python solve.py http://localhost:5000
```

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask backend with intentionally vulnerable JWT validation |
| `init_db.py` | Database initialization with dummy data and flag |
| `static/index.html` | Locked-down frontend portal |
| `static/robots.txt` | Information disclosure (backup path in comments) |
| `static/superset_config_2023.bak` | Leaked config with JWT params and routing targets |
| `static/swagger.json` | Exposed OpenAPI specification |
| `static/api_docs.html` | Human-readable API documentation |
| `Dockerfile` | Container build instructions |
| `docker-compose.yml` | One-command deployment |
| `solve.py` | Automated solver script |
