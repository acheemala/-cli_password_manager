# Interview Prep — Secure Bio Page API

## Architecture in One Paragraph

This is a **NestJS** (TypeScript) REST API. NestJS is built on top of Express and uses **dependency injection** — you declare what you need in a constructor, and the framework provides it. Everything is organized into **Modules** (`AuthModule`, `BioPagesModule`, `DatabaseModule`). The database is **pg-mem**, an entirely in-memory PostgreSQL emulator — no external DB needed. Authentication is stateless **JWT** (JSON Web Tokens) via the `passport-jwt` strategy.

---

## File-by-File Walkthrough

### `src/common/database.service.ts` — The Database Layer
- Creates three SQL tables at startup: `users`, `bio_pages`, `bio_page_shares`
- `bio_page_shares` uses a **composite primary key** `(bio_page_id, shared_with_user_id)` — naturally prevents duplicate share rows
- Seeds 3 demo pages with `owner_user_id = NULL` (ownerless/legacy pages)
- Uses `replaceQueryArgs$` from pg-mem for **parameterized queries** — prevents SQL injection
- Two methods: `query<T>()` returns rows, `exec()` runs statements that return nothing

### `src/auth/auth.service.ts` — The Auth Logic
- **signup**: lowercase email → check duplicate → bcrypt hash (cost 12) → insert user → auto-create bio page with handle derived from email prefix → issue JWT
- **login**: lowercase email → look up user → **always** run `bcrypt.compare()` even if user doesn't exist (using `DUMMY_HASH`) → if match, issue JWT
  - The dummy hash trick is the **timing-safe email enumeration defense** — without it, a failed "user not found" would return faster than a bcrypt comparison, letting an attacker discover valid emails
- `issueToken()` puts `{ sub: userId, email }` in the JWT payload — **password never touches the token**

### `src/auth/jwt.strategy.ts` — Token Validation
- Extends `PassportStrategy` — Passport.js integration
- `validate()` is called after signature verification — maps `{ sub, email }` → `{ userId, email }` and attaches to `req.user`
- Uses `ExtractJwt.fromAuthHeaderAsBearerToken()` — expects `Authorization: Bearer <token>`

### `src/auth/jwt-auth.guard.ts` — The Global Guard
- Applied globally via `APP_GUARD` in `app.module.ts` — **every route is protected by default**
- Checks for `@Public()` decorator metadata using NestJS's `Reflector` — if present, bypasses JWT check
- Secure by default: a developer who forgets to think about auth still gets a protected route

### `src/auth/public.decorator.ts` — The Opt-Out Mechanism
- Creates a custom decorator `@Public()` that attaches metadata key `IS_PUBLIC_KEY`
- Used on read-only bio page endpoints and auth endpoints (signup/login)

### `src/bio-pages/bio-pages.service.ts` — Authorization Logic
- `update()` implements the **access decision**:
  1. Fetch the page (404 if not found)
  2. Check `isOwner` (`page.ownerUserId === requestingUserId`)
  3. If not owner, query `bio_page_shares` for a share row → `isShared`
  4. Also allow `isSeedPage` (`ownerUserId === null`) — demo-only behavior
  5. Throw 403 if none apply
- `assertOwner()` is a private helper for share management — only owners can grant/revoke
- `shareWith()` is **idempotent**: checks for existing share before inserting (no error on re-share)
- **IDOR prevented**: can't access another user's shares because `assertOwner` verifies ownership before any share data is returned

### `src/bio-pages/bio-pages.controller.ts` — The Routing Layer
- Three public GET routes decorated with `@Public()`
- `POST /bio-pages` — creates with `req.user.userId` as owner (user can't inject a different owner)
- `PATCH /bio-pages/:id` — passes `req.user.userId` to service; service decides access
- Share endpoints all pass `req.user.userId` as ownerUserId — service enforces owner-only
- **Route ordering matters**: `handle/:handle` declared before `:id` — NestJS matches top-down, so "handle" would otherwise be consumed as an ID

---

## Key Security Decisions to Know Cold

| Decision | What to say |
|---|---|
| Global guard + `@Public()` | Secure by default — new routes blocked unless explicitly opened. Opposite (per-route opt-in) means one forgotten annotation = public endpoint. |
| Timing-safe login | Always run `bcrypt.compare` with a dummy hash so user-not-found and wrong-password take the same time. Without this, attackers enumerate valid emails. |
| bcrypt cost 12 | ~250ms per hash — slow enough to resist brute force, fast enough that UX doesn't suffer. Argon2id is better (memory-hard) but bcrypt is simpler and fine here. |
| JWT vs sessions | No persistent store (pg-mem is in-memory by design). Sessions need Redis/DB. JWT is stateless — works without it. Tradeoff: can't revoke tokens without a denylist. |
| HS256 vs RS256 | Single-service — both client and server are the same process, so asymmetric keys add operational complexity with zero benefit. RS256 matters for multi-service where other services need to verify tokens without the signing secret. |
| Ownership in service, not guard | Service already fetches the page for the update — putting the check there avoids a redundant DB round-trip. A separate guard would need to re-fetch the same row. |
| ValidationPipe whitelist | Strips unknown properties from request bodies. Prevents someone from sending `{ "owner_user_id": "attacker-id" }` in a PATCH to steal ownership. |

---

## What Was Deferred and Why

| Deferred | Honest Reason | What to Add |
|---|---|---|
| Rate limiting | Needed `@nestjs/throttler` wiring; prioritized auth correctness | 5 req/min on `/auth/*` endpoints |
| JWT revocation / logout | Requires server-side token store — contradicts in-memory DB | Token denylist in Redis; `POST /auth/logout` |
| Refresh tokens | Same — needs persistent store | 15min access token + long-lived refresh token rotation |
| Read-only share tier | Schema supports it (one column: `permission TEXT`); guard distinction would take more time | `permission: 'read' | 'write'` column in `bio_page_shares` |
| `JWT_SECRET` startup check | Time constraint | `if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is required')` in `main.ts` |

---

## Expected Interview Questions

### Authentication

**Q: Why bcrypt cost 12 instead of higher?**
> Cost doubles hashing time per increment. At cost 12 you're at ~250ms — meaningful protection against offline attacks. Cost 14 is ~1s, noticeable for login UX. The right number depends on hardware and acceptable latency.

**Q: What's the timing attack on login and how did you mitigate it?**
> If you return immediately on "user not found" but take 250ms on "wrong password" (bcrypt), attackers can distinguish the two by measuring response time — they enumerate valid emails. Mitigation: always run `bcrypt.compare` with a dummy hash even when the user doesn't exist. Both paths take the same time. Both return the same `"Invalid credentials"` message.

**Q: JWTs can't be revoked — how would you handle logout or compromised tokens?**
> Short-term: reduce token TTL (15min instead of 24h). Proper fix: maintain a server-side denylist (Redis set of revoked `jti` claims). On each request, check if the token's `jti` is in the denylist. Adds one Redis lookup per request — acceptable. Alternatively, use opaque tokens (sessions) with a persistent store.

**Q: What goes in the JWT payload and what specifically should not?**
> I put `{ sub: userId, email }`. The `sub` claim is standard for identifying the user. Email is a convenience for display. **Password hash must never be in the JWT** — it's transmitted in every request, potentially logged, and visible in browser dev tools. Roles can go in JWT if they don't change often; otherwise they're stale (a revoked admin still has the role until token expires).

**Q: Why HS256 and not RS256?**
> HS256 uses a single shared secret for both signing and verification — fine for a single-service app where you control both sides. RS256 uses a private key to sign and a public key to verify — useful when multiple services need to verify tokens but shouldn't be able to issue them. This is a single NestJS process so HS256 is simpler with no security loss.

---

### Authorization

**Q: What's an IDOR vulnerability and where could it appear here?**
> IDOR = Insecure Direct Object Reference. An attacker uses an ID they know (from the URL or a response) to access a resource they shouldn't. Example: `GET /bio-pages/some-uuid/shares` — without the `assertOwner` check, anyone could read another user's share list just by knowing the page ID. Mitigated by verifying `ownerUserId === req.user.userId` before returning any share data.

**Q: Why is `owner_user_id` set server-side rather than accepting it from the client?**
> `ValidationPipe` with `whitelist: true` strips unknown/undeclared properties from DTOs. `owner_user_id` is not in `CreateBioPageDto`, so even if a client sends it, it's stripped. The owner is set from `req.user.userId` — the authenticated identity from the JWT — which the client can't forge without the signing secret.

**Q: How would you implement read-only sharing?**
> Add a `permission TEXT NOT NULL DEFAULT 'write'` column to `bio_page_shares`. Update `ShareBioPageDto` to accept an optional `permission: 'read' | 'write'`. In the `update()` authorization check, query for the share row and check `permission = 'write'`. Read-only shared users would get a 403 on PATCH. Currently all public read is already open, so read-only shares only become meaningful if you add private pages.

**Q: What happens if the owner tries to revoke their own access?**
> The share system only tracks other users — the owner's access is enforced separately via the `isOwner` check. They can't revoke themselves because `bio_page_shares` rows only represent other users. The `assertOwner` check on revoke routes also prevents a shared user from revoking anyone.

**Q: Can a shared user grant sharing to someone else?**
> No. All share management endpoints call `assertOwner()` which throws 403 if the caller isn't the owner. This prevents viral/unauthorized access escalation.

---

### NestJS / Design

**Q: Why global guard with `@Public()` opt-out vs. `@UseGuards(JwtAuthGuard)` on each route?**
> Secure by default. With per-route opt-in, a developer writing a new endpoint who forgets `@UseGuards` ships an unprotected endpoint. With global opt-out, the same mistake results in a protected endpoint — the safe failure mode.

**Q: Why is the ownership check in the service and not a separate Guard?**
> The service already fetches the bio page row to perform the update. A guard would have to fetch the same row again — two DB queries for one request. Co-locating the check with the fetch avoids redundant work and is readable since it's right where the data is used.

**Q: What would you change about the database layer for production?**
> Replace pg-mem with real PostgreSQL. Add proper foreign key constraints (`REFERENCES users(id)`). Use a migration tool (Flyway, Prisma Migrate). Add an ORM or query builder (TypeORM, Drizzle) instead of raw SQL strings. Add connection pooling. The current design deliberately avoids all this since pg-mem is in-memory for the take-home.

**Q: The seed pages have `owner_user_id = NULL` — is that a security problem?**
> Yes, for production. Any authenticated user can edit them, which is intentional for demo only. In production, seed rows would have real owner IDs or be deleted. I'd add a startup check in `main.ts` that asserts no ownerless pages exist in a non-dev environment.

---

## "Write Code With Me" Scenarios to Practice

1. **Add rate limiting**: Wire `@nestjs/throttler` — `ThrottlerModule.forRoot` in `AppModule`, `@Throttle(5, 60)` on auth endpoints
2. **Add `JWT_SECRET` startup guard**: `if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') throw new Error(...)`
3. **Add a `jti` claim for revocation**: Add `randomUUID()` as `jti` in `issueToken()`, store revoked JTIs in a Set, check it in `JwtStrategy.validate()`
4. **Add `permission` column to shares**: One `ALTER TABLE` + update `ShareBioPageDto` + update authorization check in `update()`
5. **Fix the seed page NULL owner**: Add `assertNotNull(page.ownerUserId)` guard, or seed with a real system user
