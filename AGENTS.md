# Working on naf/oauth-client

NAF is a small PHP framework with optional Composer plugins. Its core owns boot,
configuration, the service container, routing, events and PSR-7 responses. Prefer existing
NAF helpers, services and extension interfaces; keep application business rules in the host.
This package declares `type: naf-plugin` and is discovered after installation in a NAF host.
The plugin repository itself is not the application's web root.

Before changing code, read the [shared contribution workflow](https://github.com/nafphp/docs/blob/main/AGENT_WORKFLOW.md)
and [release procedure](https://github.com/nafphp/docs/blob/main/RELEASING.md).
In the multi-repository workspace, the same documents are in the sibling `docs/` checkout;
use the linked copies when working from a standalone clone. Preserve other contributors' work.
Review and update user documentation with every behavior change. Source fixes use an RC branch;
verified documentation-only changes can be merged and published by the agent.

## What this plugin does

`naf/oauth-client` signs users in through external OAuth2/OIDC providers and manages granted
provider tokens. It integrates with `naf/auth` and `naf/session`; it does not run your own
authorization server. Install with `composer require naf/oauth-client` and complete provider,
account-linking, callback URL and storage setup from the user guide before invoking a flow.

## Use it

In a login handler, with an external provider registered under the example key `identity`:

```php
<?php
use function Naf\OAuth\Client\oauth;
use function Naf\redirect;

return redirect(oauth('identity')->authorizationUrl());
```

`identity` is an application-configured provider key, not a built-in provider. Ask the flow
for its `redirectUri()` when registering the callback externally. Use `oauth_token($provider)`
for granted access; it can refresh expired tokens and returns null when access is absent.
Use the existing linking/grant APIs rather than manually assembling state, PKCE or callback logic.

## Change it here

Start at [bootstrap](bootstrap.php), [Flow](src/Core/Flow.php), [provider configuration](src/),
[token handling](src/Token/) and [commands](src/Commands/). Follow existing interfaces for
account lookup/linking, state and token stores. Preserve state/nonce/PKCE validation, redirect
matching, suspended-account checks and refresh-token rotation. Do not retry single-use token
exchanges or log codes, tokens or client secrets. Browser session identity and granted external
API access are different concerns.

## Verify

Run `composer test`, `composer analyse` and `composer validate --strict`. Extend [tests](tests/)
using provider/HTTP fixtures; test callback rejection as well as success, token refresh and
account linking. Use `Tests\CommandTestCase` for commands so resolved configuration, output
URLs and diagnostics are checked through the actual CLI. Avoid live provider calls in tests.

User docs: [OAuth client](https://nafphp.github.io/docs/oauth-client/).
