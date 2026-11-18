# Virto Commerce OTP Sign-In Module

## Overview

The module lets storefront customers sign in with a one-time code sent to their email instead of a password. It signs in existing users only and does not create accounts.

## How it works

1. The storefront requests a code with `POST /api/otp/request` (`storeId`, `email`). The code is sent by the `OtpSignInEmailNotification` notification in the contact's default language or the store's default language.
2. The storefront exchanges the code for tokens with `POST /connect/token` (`grant_type=otp_email`, `storeId`, `email`, `code`).

Codes are generated and verified by the module's `OtpEmail` token provider, built on the ASP.NET Core Identity email token provider, which also defines their length and lifetime. Each code is tied to a code stamp, a random value the module keeps in the user's authentication tokens (`AspNetUserTokens`, login provider `VirtoCommerce.Otp`, name `CodeStamp`).

## Rules

* OTP sign-in works only in stores where it is enabled.
* A contact can sign in only to its own store or to a store whose trusted groups include it. Administrators and accounts that are not contacts can sign in to any store.
* Wrong codes count toward the platform account lockout. A locked account isn't sent a code. Accounts with lockout disabled can't use OTP sign-in.
* Responses that reveal whether an account exists are returned only when `PasswordLogin:DetailedErrors` is enabled. `POST /api/otp/request` reports them as a sent code, `POST /connect/token` as `invalid_code`. The sign-in log always records the real reason.
* A code works for one sign-in only: a sign-in makes every code sent before it invalid. Requesting a new code doesn't invalidate the earlier ones; they work until they expire.
* Code checks for the same user run one at a time under the platform distributed lock, and each check reads the user and the lockout again from the database, bypassing the platform user cache, so parallel requests with the same code can't both sign in and requests waiting for the lock are refused once the account is locked. With several platform instances, configure Redis (`ConnectionStrings:RedisConnectionString`); without it, the lock covers only one instance.
* Code requests are not rate-limited.
* Any change of the user's security stamp, for example a logout in another session, invalidates the codes already sent.

## Configuration

| Store setting | Description | Default |
| --- | --- | --- |
| `OtpSignIn.Enabled` | Enables OTP sign-in for the store. | `false` |

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
