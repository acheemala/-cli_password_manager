# How to Explain This as a Security Engineer

---

## The One Framing to Open Every Answer With

> "I start from the threat, not the feature. Before writing any auth code I asked: *who are the actors, what are the assets, and what's the worst thing each actor could do?* That shaped every decision."

That single sentence tells them you think in threat models, not just checkboxes.

---

## How to Explain Each Area

### Authentication

**Don't say:** "I used bcrypt to hash passwords."

**Say:**
> "Passwords are the highest-value asset in the system — if the database leaks, password hashes are the last line of defense. I chose bcrypt at cost 12, which means an attacker with the hash file still needs ~250ms per guess on modern hardware. At that speed, a billion-guess attack takes decades. Argon2id is technically stronger because it's memory-hard — meaning it resists GPU parallelism — but bcrypt is well-audited and simpler to operate. I'd use Argon2id in a greenfield production system."

**The security framing:** You're protecting against **offline attacks after a breach** — not just online login attempts. That distinction shows depth.

---

**Don't say:** "I used a dummy hash to prevent timing issues."

**Say:**
> "Login has a subtle side channel: if you return immediately when a user isn't found, but take 250ms to run bcrypt when they are found, an attacker can enumerate valid emails just by measuring response time — no password needed. I mitigated this by always running bcrypt regardless of whether the user exists, using a well-formed dummy hash. Both code paths take the same time. The error message is identical for both cases too — 'Invalid credentials' — so there's no information disclosure at the application layer either."

**The security framing:** This is **information disclosure** (STRIDE category I). You closed both the timing channel and the message channel.

---

### JWT

**Don't say:** "I put userId and email in the token."

**Say:**
> "The JWT payload is transmitted on every request, lives in browser storage, may appear in logs, and is base64-decodable — not encrypted. So I was deliberate: `sub` for the user ID (RFC 7519 standard claim), `email` as a convenience for display. Nothing sensitive. The password hash never goes near the token. For roles or permissions, I'd think carefully — stale claims in a long-lived token are a privilege escalation risk if you revoke a role but can't revoke the token."

**The security framing:** JWTs are **not confidential** — they're signed, not encrypted. Treat the payload as visible to anyone.

---

**Don't say:** "JWTs can't be logged out — I'd add a denylist."

**Say:**
> "Stateless tokens trade revocability for scalability. The threat is: compromised token stays valid until expiry. Mitigations in priority order: first, shorten the TTL (15 min access tokens with refresh reduces the window). Second, add a `jti` claim and maintain a server-side denylist — check it on every request. In production that's Redis with a TTL matching the token expiry so the set self-cleans. Third option is opaque tokens (sessions) if you have a persistent store and don't need horizontal scaling without shared state."

**The security framing:** You're talking about **blast radius** — how much damage a stolen token can do, and how to limit the window.

---

### Access Control / Authorization

**Don't say:** "I check if the user owns the page before letting them edit."

**Say:**
> "IDOR — Insecure Direct Object Reference — is one of the most common authorization failures. The attack is simple: you know a page ID from a URL or API response, so you try to PATCH or read shares for a page you don't own. The fix isn't hiding IDs — it's enforcing authorization server-side on every operation. I verify ownership at the service layer, where the data lives, not at the routing layer. That way there's no code path that touches data without the check happening."

**The security framing:** IDs are never secret. **Authorization must be enforced at every data access**, not just at the route entry point.

---

**Don't say:** "I used a global guard so all routes need auth."

**Say:**
> "I applied the principle of **secure by default**. The global `JwtAuthGuard` means every new route written by any developer is authenticated — they have to explicitly opt out with `@Public()`. The alternative — opt-in guards per route — means one forgotten decorator ships an unprotected endpoint to production. I'd rather the default failure mode be a 401 than an exposed endpoint."

**The security framing:** You're talking about **failure modes** and **developer ergonomics as a security property** — not just your own code, but the safety of the whole system over time.

---

**Don't say:** "I validated the request body to prevent bad data."

**Say:**
> "There's a class of attack where you inject fields the server shouldn't trust — sending `owner_user_id` in a PATCH body to steal ownership of a page, for example. `ValidationPipe` with `whitelist: true` strips any property not declared in the DTO, and `forbidNonWhitelisted` rejects the request entirely. Combined with setting `owner_user_id` from `req.user` (the JWT-verified identity) rather than the body, there's no path for a client to influence the ownership binding."

**The security framing:** This is **mass assignment / parameter tampering**. You know the attack category, not just the fix.

---

### What You Deferred — How a Security Person Frames It

**Don't say:** "I didn't have time for rate limiting."

**Say:**
> "I consciously prioritized. Rate limiting on auth endpoints matters — credential stuffing is real — but it's also detachable: you can add `@nestjs/throttler` without touching the auth logic. What you can't retrofit easily is a broken access control model or a timing side channel. I got the security-critical parts correct first and documented rate limiting as the highest-priority follow-up."

**The security framing:** Shows you understand **risk prioritization** — not everything is equal, and you made a deliberate call.

---

**Don't say:** "Refresh tokens were too hard."

**Say:**
> "24-hour tokens are a tradeoff I made explicitly given the in-memory database constraint. Refresh tokens require a persistent, server-side store — you need to validate and rotate them, which contradicts the pg-mem design. In a production system I'd use 15-minute access tokens with a rotating refresh token stored as an httpOnly cookie, so the refresh token isn't accessible to JavaScript at all. That removes localStorage XSS as a token theft vector."

**The security framing:** You know the **full threat model** around token storage, not just that refresh tokens exist.

---

## Phrases That Signal Security Depth

Use these naturally — they show you think in frameworks, not checklists.

| Phrase | What it signals |
|---|---|
| "The threat here is..." | You start from attacks, not features |
| "The blast radius if this goes wrong is..." | You think about impact, not just likelihood |
| "Secure by default means..." | You think about system safety over time |
| "This is a STRIDE category [X] issue..." | You use a threat modeling framework |
| "I'd prioritize this over [Y] because..." | You can rank risks, not just list them |
| "The attack is [X], the mitigation is [Y], the residual risk is [Z]" | You think in complete threat-mitigation pairs |
| "This is defense in depth because..." | You layer controls rather than relying on one |
| "The failure mode if this is missing is..." | You reason about what breaks, not just what works |

---

## The Meta-Answer for Any Question You're Unsure About

If they ask something you didn't implement or aren't sure of:

> "I didn't implement that in the time I had, but my approach would be to start with the threat: what's the attack, what's the blast radius, what's the simplest control that closes it. Then I'd look at whether that control has its own attack surface — because adding complexity can introduce new vulnerabilities. What's the specific scenario you're thinking about?"

Turning it back into a conversation shows you think collaboratively, not defensively — and buys you time to think.

---

## One-Sentence Summary of Everything

> "Security isn't a feature I added — it's a set of properties I maintained throughout: the right secrets in the right places, trust never derived from client input, authorization enforced at data access not routing, and failure modes that are safe rather than open."
