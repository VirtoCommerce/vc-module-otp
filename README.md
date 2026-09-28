# Virto Commerce OTP Sign-In Module

## Overview

The module lets storefront customers sign in with a one-time code sent to their email instead of a password. It signs in existing users only and does not create accounts.

## How it works

1. The storefront requests a code with `POST /api/otp/request` (`storeId`, `email`). The code is sent by the `OtpSignInEmailNotification` notification in the contact's default language or the store's default language.
2. The storefront exchanges the code for tokens with `POST /connect/token` (`grant_type=otp_email`, `storeId`, `email`, `code`).

Codes are generated and verified by the ASP.NET Core Identity `"Email"` token provider, which also defines their length and lifetime. The module stores nothing.

## Rules

* OTP sign-in works only in stores where it is enabled.
* A contact can sign in only to its own store or to a store whose trusted groups include it. Administrators and accounts that are not contacts can sign in to any store.
* Wrong codes count toward the platform account lockout. Accounts with lockout disabled can't use OTP sign-in.
* Responses that reveal whether an account exists are returned only when `PasswordLogin:DetailedErrors` is enabled. The request endpoint reports them as `CodeSent`, the token grant as `invalid_code`. The sign-in log always records the real reason.
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
