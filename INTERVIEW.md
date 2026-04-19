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

## Live Coding Scenarios — Full Sample Code

Each section shows what the interviewer may ask you to write, and the complete working answer.

---

### 1. Add Rate Limiting to Auth Endpoints

**What they ask:** "Add rate limiting so `/auth/login` and `/auth/signup` can't be hammered."

**Step 1 — install** (mention this first): `npm install @nestjs/throttler`

**Step 2 — wire into AppModule** (`src/app.module.ts`):
```typescript
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 5 }]), // 5 requests per 60 seconds
    DatabaseModule,
    AuthModule,
    BioPagesModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: ThrottlerGuard }, // add second global guard
  ],
})
export class AppModule {}
```

**Step 3 — apply to auth controller** (`src/auth/auth.controller.ts`):
```typescript
import { Throttle, SkipThrottle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5/min per IP
  @Post('signup')
  signup(@Body() dto: SignupDto) { ... }

  @Public()
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @HttpCode(200)
  @Post('login')
  login(@Body() dto: LoginDto) { ... }
}
```

**Why:** Auth endpoints are the highest-value brute-force target. The rest of the API can remain unthrottled or get a looser limit.

---

### 2. JWT_SECRET Startup Guard

**What they ask:** "What happens if someone deploys without setting JWT_SECRET? Fix it."

**Current problem:** Falls back to `'dev-secret-change-in-production'` — tokens signed in dev work in prod if env var is missing.

**Fix in `src/main.ts`**:
```typescript
async function bootstrap() {
  // Fail fast — never start in production with the fallback dev secret
  if (!process.env.JWT_SECRET) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET environment variable is required in production');
    }
    console.warn('[WARN] JWT_SECRET not set — using insecure dev fallback');
  }

  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: '*' });
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true, forbidNonWhitelisted: true }));
  await app.listen(3000);
}
```

**Why throw vs warn:** In production a misconfigured secret is a critical security failure — fail fast is better than silently running insecure.

---

### 3. JWT Revocation with jti Claims (Logout)

**What they ask:** "How would you add a logout endpoint? JWTs can't be revoked — show me how you'd handle it."

**Step 1 — add `jti` to token** (`src/auth/auth.service.ts`):
```typescript
import { randomUUID } from 'crypto';

// In-memory denylist — in production this would be Redis with TTL matching token expiry
private readonly revokedTokens = new Set<string>();

private issueToken(userId: string, email: string): string {
  const jti = randomUUID(); // unique token ID
  return this.jwtService.sign({ sub: userId, email, jti });
}

revokeToken(jti: string): void {
  this.revokedTokens.add(jti);
}

isRevoked(jti: string): boolean {
  return this.revokedTokens.has(jti);
}
```

**Step 2 — check denylist in JWT strategy** (`src/auth/jwt.strategy.ts`):
```typescript
export type JwtPayload = { sub: string; email: string; jti: string };

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET ?? 'dev-secret-change-in-production',
    });
  }

  validate(payload: JwtPayload): AuthUser {
    if (this.authService.isRevoked(payload.jti)) {
      throw new UnauthorizedException('Token has been revoked');
    }
    return { userId: payload.sub, email: payload.email };
  }
}
```

**Step 3 — add logout endpoint** (`src/auth/auth.controller.ts`):
```typescript
import { Request } from '@nestjs/common';

@Post('logout')
@HttpCode(200)
logout(@Request() req: { user: AuthUser & { jti: string } }) {
  this.authService.revokeToken(req.user.jti); // add jti to AuthUser type too
  return { message: 'Logged out' };
}
```

**Tradeoff to mention:** The `Set<string>` is in-memory — revocations are lost on restart. Production fix: Redis with `SETEX jti "" <expiry_seconds>` so revoked tokens auto-expire when the JWT would have expired anyway.

---

### 4. Read-Only Share Tier

**What they ask:** "How would you add a permission level to shares — read vs edit?"

**Step 1 — update the schema** (`src/common/database.service.ts`):
```typescript
this.db.public.none(`
  CREATE TABLE bio_page_shares (
    bio_page_id         TEXT NOT NULL,
    shared_with_user_id TEXT NOT NULL,
    permission          TEXT NOT NULL DEFAULT 'write',  -- 'read' | 'write'
    PRIMARY KEY (bio_page_id, shared_with_user_id)
  );
`);
```

**Step 2 — update the DTO** (`src/bio-pages/dto/share-bio-page.dto.ts`):
```typescript
import { IsEmail, IsIn, IsOptional } from 'class-validator';

export class ShareBioPageDto {
  @IsEmail()
  email!: string;

  @IsOptional()
  @IsIn(['read', 'write'])
  permission?: 'read' | 'write';  // defaults to 'write' if omitted
}
```

**Step 3 — update shareWith INSERT** (`src/bio-pages/bio-pages.service.ts`):
```typescript
shareWith(bioPageId: string, ownerUserId: string, dto: ShareBioPageDto): ShareRow[] {
  // ... existing owner/self-share/user-not-found checks ...

  const permission = dto.permission ?? 'write';
  const existing = this.database.query<{ shared_with_user_id: string }>(
    'SELECT shared_with_user_id FROM bio_page_shares WHERE bio_page_id = $1 AND shared_with_user_id = $2;',
    [bioPageId, target.id],
  );
  if (existing.length === 0) {
    this.database.exec(
      'INSERT INTO bio_page_shares (bio_page_id, shared_with_user_id, permission) VALUES ($1, $2, $3);',
      [bioPageId, target.id, permission],
    );
  }
  return this.getShares(bioPageId);
}
```

**Step 4 — enforce in update()** (`src/bio-pages/bio-pages.service.ts`):
```typescript
// Replace the current isShared check with a permission-aware check:
const shared = this.database.query<{ permission: string }>(
  'SELECT permission FROM bio_page_shares WHERE bio_page_id = $1 AND shared_with_user_id = $2;',
  [id, requestingUserId],
);
const hasWriteAccess = shared.length > 0 && shared[0].permission === 'write';

if (!isOwner && !hasWriteAccess && !isSeedPage) {
  throw new ForbiddenException('You do not have permission to edit this bio page');
}
```

**Note to mention:** Read-only sharing only adds value once you have private bio pages. Right now all pages are publicly readable, so a read-only grant between users provides nothing extra.

---

### 5. Fix the Seed Page NULL Owner Problem

**What they ask:** "The seed pages have no owner — any authenticated user can edit them. How would you fix that in production?"

**Option A — Startup assertion** (`src/main.ts`):
```typescript
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // ...

  if (process.env.NODE_ENV === 'production') {
    const db = app.get(DatabaseService);
    const ownerless = db.query('SELECT id FROM bio_pages WHERE owner_user_id IS NULL;');
    if (ownerless.length > 0) {
      throw new Error(`Production startup blocked: ${ownerless.length} ownerless bio page(s) found`);
    }
  }

  await app.listen(3000);
}
```

**Option B — Remove seed pages entirely** (cleanest for production):
```typescript
// In database.service.ts constructor — only seed in dev:
if (process.env.NODE_ENV !== 'production') {
  for (const row of seedRows) {
    this.exec(`INSERT INTO bio_pages ...`, [...]);
  }
}
```

**Option C — Give seed pages a system owner**:
```typescript
// Create a system user first, then seed with their ID
const systemUserId = randomUUID();
this.exec(
  `INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4);`,
  [systemUserId, 'system@internal', 'not-a-real-hash', now],
);
// Then seed pages with owner_user_id = systemUserId
```

---

### 6. Add a `@CurrentUser` Decorator (Clean Code Question)

**What they ask:** "The `@Request() req` pattern is repetitive across every controller. How would you clean that up?"

**Create `src/auth/current-user.decorator.ts`**:
```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthUser } from './jwt.strategy';

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthUser => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
```

**Before (controller)**:
```typescript
@Patch(':id')
update(@Param('id') id: string, @Request() req: { user: AuthUser }, @Body() payload: UpdateBioPageDto) {
  return this.bioPagesService.update(id, payload, req.user.userId);
}
```

**After (cleaner)**:
```typescript
@Patch(':id')
update(@Param('id') id: string, @CurrentUser() user: AuthUser, @Body() payload: UpdateBioPageDto) {
  return this.bioPagesService.update(id, payload, user.userId);
}
```

---

### 7. Write the `@Public()` Decorator from Scratch

**What they ask:** "Walk me through how `@Public()` works and write it yourself."

```typescript
import { SetMetadata } from '@nestjs/common';

// A constant key used to store and read the metadata flag
export const IS_PUBLIC_KEY = 'isPublic';

// SetMetadata attaches { isPublic: true } to the route handler's metadata
// The JwtAuthGuard reads this via Reflector to decide whether to skip auth
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

**How the guard reads it** (`jwt-auth.guard.ts`):
```typescript
canActivate(context: ExecutionContext) {
  // Reflector checks the handler first, then the class — @Public() on either works
  const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
    context.getHandler(), // method-level decorator
    context.getClass(),   // class-level decorator
  ]);
  if (isPublic) return true;          // skip JWT check entirely
  return super.canActivate(context);  // run passport-jwt validation
}
```

---

### 8. Write the Timing-Safe Login from Scratch

**What they ask:** "Show me the timing attack and write the protection."

**Vulnerable version** (do NOT write this):
```typescript
// BAD — returns fast if user not found, slow if wrong password
async login(dto: LoginDto) {
  const user = await findUserByEmail(dto.email);
  if (!user) throw new UnauthorizedException('Invalid credentials'); // fast return ← timing leak
  const match = await bcrypt.compare(dto.password, user.password_hash); // slow
  if (!match) throw new UnauthorizedException('Invalid credentials');
}
```

**Correct version** (what's in the code):
```typescript
const DUMMY_HASH = '$2b$12$invalidhashfortimingprotectionAAAAAAAAAAAAAAAAAAAAAAAAA';

async login(dto: LoginDto): Promise<{ accessToken: string }> {
  const email = dto.email.toLowerCase();
  const rows = this.database.query<UserRow>('SELECT * FROM users WHERE email = $1;', [email]);
  const user = rows[0];

  // Always call bcrypt.compare — if user is missing, compare against DUMMY_HASH.
  // Both code paths take ~250ms. Without this, "user not found" returns in <1ms
  // and attackers can enumerate valid emails by measuring response time.
  const hashToCompare = user?.password_hash ?? DUMMY_HASH;
  const match = await bcrypt.compare(dto.password, hashToCompare);

  if (!user || !match) {
    throw new UnauthorizedException('Invalid credentials'); // same message for both cases
  }

  return { accessToken: this.issueToken(user.id, user.email) };
}
```

**Key points to say:**
- Same error message for "wrong email" and "wrong password" — no information disclosure
- `DUMMY_HASH` must be a valid bcrypt hash format with the correct cost factor (`$2b$12$...`) so bcrypt doesn't short-circuit
- `!user || !match` is evaluated after the bcrypt call — never before

---

### 9. Write a Custom Ownership Guard (Alternative Architecture)

**What they ask:** "How would you extract the ownership check into a reusable Guard instead of keeping it in the service?"

```typescript
// src/bio-pages/bio-page-owner.guard.ts
import { CanActivate, ExecutionContext, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { DatabaseService } from '../common/database.service';

@Injectable()
export class BioPageOwnerGuard implements CanActivate {
  constructor(private readonly database: DatabaseService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const userId = req.user?.userId;
    const pageId = req.params.id;

    const rows = this.database.query<{ owner_user_id: string }>(
      'SELECT owner_user_id FROM bio_pages WHERE id = $1;',
      [pageId],
    );
    if (!rows[0]) throw new NotFoundException('Bio page not found');
    if (rows[0].owner_user_id !== userId) throw new ForbiddenException('Not the owner');

    return true;
  }
}
```

**Apply to controller**:
```typescript
@UseGuards(BioPageOwnerGuard)
@Delete(':id/share/:targetUserId')
revokeShare(...) { ... }
```

**Tradeoff to mention:** This is cleaner for share management routes (owner-only, full stop), but for `PATCH` it doesn't work cleanly because shared users also need access. That's why the ownership + share check lives in the service for `update()` — it needs both checks in one place, and already fetches the page.

---

### 10. Add Security Headers with Helmet

**What they ask:** "What HTTP security headers would you add?"

```typescript
// src/main.ts
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Sets: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
  // Strict-Transport-Security, Content-Security-Policy, etc.
  app.use(helmet());

  // Tighten CORS for production — don't use '*'
  app.enableCors({
    origin: process.env.ALLOWED_ORIGIN ?? 'http://localhost:5173',
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Authorization', 'Content-Type'],
  });

  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true, forbidNonWhitelisted: true }));
  await app.listen(3000);
}
```

**Headers helmet adds (know these):**
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing attacks
- `X-Frame-Options: DENY` — prevents clickjacking via iframes
- `Strict-Transport-Security` — forces HTTPS
- `Content-Security-Policy` — restricts what resources the browser can load

---

### 11. Validate Password Strength (Extending the DTO)

**What they ask:** "The password only requires 8 characters. How would you make it stronger?"

```typescript
// src/auth/dto/signup.dto.ts
import { IsEmail, IsString, Matches, MinLength } from 'class-validator';

export class SignupDto {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  // Requires: at least one uppercase, one lowercase, one digit, one special char
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/, {
    message: 'Password must contain uppercase, lowercase, number, and special character',
  })
  password!: string;
}
```

**Tradeoff to mention:** NIST SP 800-63B (the current standard) actually recommends against complexity rules and instead recommends length + checking against known breached passwords. In production you'd check the password against the HaveIBeenPwned API (k-anonymity prefix search) rather than enforcing character classes.

---

### 12. Add Pagination to `GET /bio-pages`

**What they ask:** "The list endpoint returns all bio pages — how would you add pagination?"

**DTO**:
```typescript
// src/bio-pages/dto/list-bio-pages.dto.ts
import { Type } from 'class-transformer';
import { IsInt, IsOptional, Max, Min } from 'class-validator';

export class ListBioPagesDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(50)
  limit?: number = 20;
}
```

**Service**:
```typescript
findAll(query: ListBioPagesDto): { data: BioPage[]; total: number } {
  const limit = query.limit ?? 20;
  const offset = ((query.page ?? 1) - 1) * limit;

  const rows = this.database.query<BioPageRow>(
    'SELECT * FROM bio_pages ORDER BY created_at DESC LIMIT $1 OFFSET $2;',
    [limit, offset],
  );
  const total = this.database.query<{ count: string }>('SELECT COUNT(*) as count FROM bio_pages;')[0];

  return { data: rows.map(this.toBioPage), total: parseInt(total.count) };
}
```

**Controller**:
```typescript
@Public()
@Get()
findAll(@Query() query: ListBioPagesDto) {
  return this.bioPagesService.findAll(query);
}
```

---

### Quick Reference — Things to Be Able to Write in <2 Minutes

| Snippet | Key thing to remember |
|---|---|
| `@Public()` decorator | `SetMetadata(IS_PUBLIC_KEY, true)` — guard reads it via `Reflector` |
| Timing-safe login | `user?.password_hash ?? DUMMY_HASH` — always run bcrypt |
| `assertOwner()` | `if (page.ownerUserId !== userId) throw new ForbiddenException(...)` |
| JWT payload | `{ sub: userId, email }` — never password, never sensitive data |
| Global guard registration | `{ provide: APP_GUARD, useClass: JwtAuthGuard }` in `AppModule` providers |
| Parameterized query | `replaceQueryArgs$(sql, [param1, param2])` — never string interpolation |
| `ValidationPipe` options | `whitelist: true, forbidNonWhitelisted: true, transform: true` |
