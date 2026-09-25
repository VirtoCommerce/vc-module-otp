# Virto Commerce OTP Sign-In Module

## Overview

The OTP Sign-In module enables B2B storefront customers to sign in with a one-time code emailed to them, instead of a password — useful on shared or mobile devices where remembering or resetting a password is inconvenient. Store administrators can enable or disable the OTP sign-in experience per store, without a code change.

The module serves returning customers only: a code is only useful for signing in to an existing account, it does not create new accounts.

## Key features

* **Email one-time codes** — a code is generated and validated using ASP.NET Core Identity's built-in stateless token provider (`UserManager.GenerateUserTokenAsync`/`VerifyUserTokenAsync`, `"Email"` provider); no code, hash, or salt is ever persisted by this module.
* **Per-store enablement** — OTP sign-in can be turned on or off independently per store.
* **Shared account lockout** — wrong-code attempts are recorded with the platform's own `UserManager.AccessFailedAsync`/`IsLockedOutAsync`, the same lockout used for password sign-in (`IdentityOptions.Lockout`). A user already faces this exposure through the password form alone, so sharing the counter does not introduce a new attack vector.
* **Timing-equalized responses** — response time for code requests is equalized across outcomes (disabled/sent), so timing can't be used to probe whether an email is registered.
* **Reuses the platform's external sign-in pipeline** — once a code is verified, a pending external login is established the same way an OAuth provider would after a successful challenge, so the platform's existing `IExternalSignInService` and `external_sign_in` token grant complete the sign-in — no platform changes required.
* **Delivery via `VirtoCommerce.Notifications`** — the code is sent through the standard notification pipeline (`OtpSignInEmailNotification`), so it inherits whatever email gateway (SMTP/SendGrid/Microsoft Graph) the store already uses.

Code length and lifetime are controlled by the platform's `"Email"` token provider and are not configurable per store.

The module deliberately has no request rate limiting (per-email cooldown, per-IP throttling, etc.). An earlier version added one using `System.Threading.RateLimiting`/`Microsoft.AspNetCore.RateLimiting`, but those primitives hold their counters in local process memory — with more than one platform instance behind a load balancer, each instance enforces the limit independently, so the effective limit becomes "configured value × instance count" instead of a real cap, and an operator setting a strict value would get a false sense of protection. Rather than ship a limiter that quietly stops meaning what its own setting says in a scaled-out deployment, it was removed; add it back only with a distributed store (e.g. Redis) if this module ever needs it.

Because the code is derived from the user's `SecurityStamp` (not stored anywhere by this module), anything that rotates that stamp invalidates every code already issued for that user — including a currently valid, not-yet-used one. The platform's own `GET /api/security/logout` does exactly this by design (to revoke any other outstanding cookies/tokens for that user on sign-out). So if the same account is signed in elsewhere (another tab/device/test session) and that other session logs out while a code is pending, the code silently stops working — not a bug in this module, just a consequence of tying the code to the platform's own session-invalidation mechanism.

## Configuration

All settings are registered under the `VirtoCommerce.Otp` module and can be managed from the Admin Portal (*Settings*) or via the Platform settings API.

### Store settings (*Store → OTP Sign-In → General*)

| Setting | Description | Default |
| --- | --- | --- |
| `OtpLogin.Enabled` | Enables OTP sign-in for the store. | `false` |

### Permissions

* `otp:access` — manage OTP sign-in settings.

### Notifications

Registers the `OtpSignInEmailNotification` template (*Notifications → Notification list*, or per store under *Store → Notifications*), carrying the code.

## Architecture

```
src/
├── VirtoCommerce.Otp.Core   # Domain contracts: models, ModuleConstants (settings/permissions), notifications
├── VirtoCommerce.Otp.Data   # Service implementation
└── VirtoCommerce.Otp.Web    # Module host: Module.cs, REST controller, external sign-in integration, manifest
tests/
└── VirtoCommerce.Otp.Tests  # Unit tests
```

The module has no database of its own — code generation, verification, and lockout all delegate to `UserManager<ApplicationUser>`.

### Services (Core → Data)

| Contract | Implementation | Responsibility |
| --- | --- | --- |
| `IOtpService` | `OtpService` | Requests and verifies codes via `UserManager`; enforces the shared account lockout. |

### Security integration

* `OtpExternalSignInProvider` — `IExternalSignInProvider` registration (`AuthenticationType = "Otp"`, `AllowCreateNewUser = false`).
* `OtpExternalSignInService` — after a successful verification, establishes a pending external login cookie so the platform's own `IExternalSignInService`/`external_sign_in` token grant completes the sign-in. Deliberately does not implement `IExternalSignInService` itself, since the platform registers a single instance of that interface shared by all external sign-in providers (Google, Azure AD, etc.) — replacing it would break those.

### REST API surface

Hosted by `VirtoCommerce.Otp.Web`, anonymous access:

* `POST /api/otp/request` — request a code for an email.
* `POST /api/otp/verify` — verify a code; on success, completes the external sign-in.

## References

* [Deployment](https://docs.virtocommerce.org/platform/developer-guide/Tutorials-and-How-tos/Tutorials/deploy-module-from-source-code/)
* [Installation](https://docs.virtocommerce.org/platform/user-guide/modules-installation/)
* [Home](https://virtocommerce.com)
* [Community](https://www.virtocommerce.org)

## License

Copyright (c) Virto Solutions LTD.  All rights reserved.

Licensed under the Virto Commerce Open Software License (the "License"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at

<https://virtocommerce.com/open-source-license>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.
