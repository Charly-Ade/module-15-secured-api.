# Module 15 - Secured Express API

TypeScript + Express 5 account/transactions API with bcrypt auth, JWT access/refresh tokens, RBAC + ownership checks, and a hardening pass. See **NOTES.md** for the full security checklist, `npm audit` output and known gaps.

## Run it
```bash
npm install
cp .env.example .env        # then fill in the two JWT secrets (command inside the file)
npm run dev                 # tsx watch
npm test                    # 30 tests (bcrypt cost 12 is slow on purpose, ~20s)
npm run typecheck && npm run lint && npm run build
```
Optional: set `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` in `.env` to create an admin at startup (the only way to get one).

## Endpoints
| Method & path | Access | Notes |
|---|---|---|
| `POST /api/auth/register` | public, strict rate limit | `{name,email,password}` → 201, role always `user` |
| `POST /api/auth/login` | public, strict rate limit | → `{user, accessToken, refreshToken, expiresIn}` |
| `POST /api/auth/refresh` | public | `{refreshToken}` → new pair (old one is now dead) |
| `POST /api/auth/logout` | public | `{refreshToken}` → 204 |
| `GET /api/auth/me` | logged in | |
| `GET /api/accounts` | logged in | own accounts; admin sees all |
| `POST /api/accounts` | logged in | owner = you |
| `GET /api/accounts/:id` | owner or admin | else **403** |
| `GET /api/accounts/:id/transactions` | owner or admin | else **403** |
| `POST /api/transactions` | owner of the account, or admin | else **403** |
| `GET /api/admin/users` | **admin only** | non-admin → **403**, anonymous → 401 |

Send tokens as `Authorization: Bearer <accessToken>`.
