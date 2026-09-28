# Virto Commerce OTP Sign-In Module

## Overview

The OTP Sign-In module enables B2B storefront customers to sign in with a one-time code emailed to them, instead of a password — useful on shared or mobile devices where remembering or resetting a password is inconvenient. Store administrators can enable or disable the OTP sign-in experience per store, without a code change.

The module serves returning customers only: a code is only useful for signing in to an existing account, it does not create new accounts.

## Key features

* **Email one-time codes** — a code is generated and validated using ASP.NET Core Identity's built-in stateless token provider (`UserManager.GenerateUserTokenAsync`/`VerifyUserTokenAsync`, `"Email"` provider); no code, hash, or salt is ever persisted by this module.
* **Per-store enablement** — OTP sign-in can be turned on or off independently per store.
* **Shared account lockout** — wrong-code attempts are recorded with the platform's own `UserManager.AccessFailedAsync`/`IsLockedOutAsync`, the same lockout used for password sign-in (`IdentityOptions.Lockout`). A user already faces this exposure through the password form alone, so sharing the counter does not introduce a new attack vector.
* **No account enumeration** — outcomes that reveal whether an account exists (unknown email, duplicate email, account without lockout, account from another store) are reported as "code sent" by the request endpoint and as `invalid_code` by the token grant, unless `PasswordLogin:DetailedErrors` is enabled. The sign-in log always records the real reason. Response time for code requests is equalized between sent and not-sent outcomes, so timing can't be used to probe either.
* **Custom token grant** — the code is exchanged for tokens at the platform's `POST /connect/token` endpoint with `grant_type=otp_email` and the `storeId`, `email` and `code` parameters. The handler builds on the platform's `GrantTypeHandlerBase`, so token request validators, claim providers and the sign-in log apply the same way as for password sign-in.
* **Delivery via `VirtoCommerce.Notifications`** — the code is sent through the standard notification pipeline (`OtpSignInEmailNotification`), so it inherits whatever email gateway (SMTP/SendGrid/Microsoft Graph) the store already uses.

Code length and lifetime are controlled by the platform's `"Email"` token provider and are not configurable per store.

The module deliberately has no request rate limiting (per-email cooldown, per-IP throttling, etc.). In-process limiters such as `System.Threading.RateLimiting`/`Microsoft.AspNetCore.RateLimiting` hold their counters in local process memory — with more than one platform instance behind a load balancer, each instance enforces the limit independently, so the effective limit becomes "configured value × instance count" instead of a real cap. A meaningful limit needs a distributed store (e.g. Redis).

Because the code is derived from the user's `SecurityStamp` (not stored anywhere by this module), anything that rotates that stamp invalidates every code already issued for that user — including a currently valid, not-yet-used one. The platform's own `GET /api/security/logout` does exactly this by design (to revoke any other outstanding cookies/tokens for that user on sign-out). So if the same account is signed in elsewhere (another tab/device/test session) and that other session logs out while a code is pending, the code silently stops working — not a bug in this module, just a consequence of tying the code to the platform's own session-invalidation mechanism.

## Configuration

All settings are registered under the `VirtoCommerce.OTP` module and can be managed from the Admin Portal (*Settings*) or via the Platform settings API.

### Store settings (*Store → OTP Sign-In → General*)

| Setting | Description | Default |
| --- | --- | --- |
| `OtpSignIn.Enabled` | Enables OTP sign-in for the store. | `false` |

### Notifications

Registers the `OtpSignInEmailNotification` template (*Notifications → Notification list*, or per store under *Store → Notifications*), carrying the code.

## Architecture

```
src/
├── VirtoCommerce.Otp.Core   # Domain contracts: models, ModuleConstants (settings, grant type), notifications
├── VirtoCommerce.Otp.Data   # Service implementation and token grant handler
└── VirtoCommerce.Otp.Web    # Module host: Module.cs, REST controller, manifest
tests/
└── VirtoCommerce.Otp.Tests  # Unit tests
```

The module has no database of its own — code generation, verification, and lockout all delegate to `UserManager<ApplicationUser>`.

### Services (Core → Data)

| Contract | Implementation | Responsibility |
| --- | --- | --- |
| `IOtpService` | `OtpService` | Requests and verifies codes via `UserManager`; enforces the shared account lockout. |

### Security integration

* `OtpGrantTypeHandler` — handles the `otp_email` grant: verifies the code with `IOtpService` and signs the user in through the platform's `GrantTypeHandlerBase`. Registered with `AddGrantTypeHandler`, which also enables the grant type in OpenIddict.

### REST API surface

Hosted by `VirtoCommerce.Otp.Web`, anonymous access:

* `POST /api/otp/request` — request a code for an email in a store (`storeId`, `email`).

The code itself is verified by the `otp_email` token grant at `POST /connect/token`, not by this module's REST API.

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
