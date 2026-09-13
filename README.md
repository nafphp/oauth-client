<div align="center">

![NAF](assets/naf-logo-small-square.png)

[![NAF OAuth Client Plugin](https://github.com/nafphp/oauth-client/actions/workflows/php.yml/badge.svg)](https://github.com/nafphp/oauth-client/actions/workflows/php.yml)

</div>

[← Back to NAF](https://github.com/nafphp/framework)

---

# naf/oauth-client

> **Sign people in with Google, Microsoft or any OpenID Connect provider — and keep your own user model.**

```php
<?= oauth_button('google') ?>
```

That is the whole integration. The routes, the protocol and the account lookup are already
wired; what is left for you is the one decision nobody else can make — see
[Which account is this?](#which-account-is-this)

> 🧩 Part of the official NAF plugin collection.
> Install it when people should sign in with an account they already have.

---

## What this plugin is

It answers one question — **who does the provider say this is?** — and hands back an
`ExternalIdentity`: an issuer, a subject, and the claims that came with them.

Everything the protocol asks for in between is not configurable, because none of it is a
decision an application should be making:

| | |
| --- | --- |
| **PKCE** | S256, always, for confidential clients too |
| **`state`** | random, stored server-side, consumed once |
| **`nonce`** | issued and checked against the ID token |
| **Signature** | always verified against the provider's published keys, wherever there is an ID token |
| **Algorithm** | pinned to what the provider publishes, never read from the token's own header |
| **Claims** | `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, `sub` — all required, all checked |
| **Metadata** | the document has to name the issuer you configured before anything in it is used |
| **Redirect URI** | derived from your public URL, sent exactly, never taken from a request |
| **Transport** | https only, and no redirects followed while credentials are in flight |
| **Key rotation** | an unknown key id reloads the key set, once, with a cooldown |

A provider whose keys cannot be read makes the login **fail**. It never makes the check optional.

The configured issuer is the trust anchor — the one thing you actually stated about a provider.
Everything else, endpoints and signing keys included, arrives over the network, so a discovery
document has to prove it belongs to that issuer before anything in it is used and before a
client secret is sent to an address it names.

Signing somebody in is the whole of it by default, and stores nothing the provider issued. An
application that also has to *act* at the provider afterwards — read a calendar, list
repositories — can keep those tokens instead; that is opt-in and lives in
[Calling the provider afterwards](#calling-the-provider-afterwards).

---

## 📥 Installation

```bash
composer require naf/oauth-client
```

`naf/auth` and `naf/session` come with it — the first owns your accounts, the second is
what binds a login to one browser. A PDO connection is found on its own when `naf/database`
is configured; nothing to bind. Add `naf/client` for the PSR-18 transport (or bind your
own to `Psr\Http\Client\ClientInterface`), and `naf/database` if you want the account-link
table as a migration.

```bash
vendor/bin/nix db:migrate up          # creates oauth_identities
```

---

## Configuration

### Google

The whole thing:

```php
// app/config.php
return [
    'public_url' => 'https://example.com',
    'auth' => [
        'users'  => ['model' => App\Models\User::class],
        'logins' => [
            'google' => [
                'client_id'     => $_ENV['GOOGLE_CLIENT_ID'],
                'client_secret' => $_ENV['GOOGLE_CLIENT_SECRET'],
            ],
        ],
    ],
];
```

Two things: where your accounts live, and which logins you offer. The connection, the callback
routes, the session, the link table, the HTTP transport and the landing page are all taken from
what is already there.

Then ask what to register with the provider:

```bash
vendor/bin/nix oauth:discover google
```

It reads the provider's metadata, proves the setup resolves, and prints the callback URL to
paste into their console.

**`public_url` is required and has no default.** Inside a request the only candidates are the
`Host` and `X-Forwarded-*` headers, and those are set by whoever is calling. Every redirect URI
is built from this one value, so it is stated once rather than guessed.

### One provider, several logins

The key names the login; `driver` says which provider is behind it. Keeping them apart is what
lets you offer the same provider twice under names of your choosing:

```php
'logins' => [
    'staff'    => ['driver' => 'microsoft', 'tenant' => 'acme.example', 'client_id' => …, 'client_secret' => …],
    'partners' => ['driver' => 'microsoft', 'tenant' => 'partner.example', 'client_id' => …, 'client_secret' => …],
],
```

Each gets its own callback (`/auth/staff/callback`, `/auth/partners/callback`), its own button
and its own credentials. Without a `driver`, the key is the driver — which is why `google` above
needs nothing else.

### Microsoft

Microsoft needs one more thing: **which accounts may sign in.**

```php
'microsoft' => [
    'client_id'     => $_ENV['MS_CLIENT_ID'],
    'client_secret' => $_ENV['MS_CLIENT_SECRET'],
    'tenant'        => '8f3a1c94-…',   // directory id, or a verified domain
],
```

A single named tenant pins the issuer by itself. The multi-tenant values — `common`,
`organizations`, `consumers` — mean *any* organisation in the world may sign in, so they will
not start without you saying who:

```php
'tenant'          => 'common',
'allowed_tenants' => ['8f3a1c94-…', 'b21d…'],   // or ['*'] to accept everyone
```

Without `allowed_tenants` the setup raises a `ConfigurationException` naming the key. This is
deliberate: with `common`, Microsoft's discovery document gives its issuer as a *template*, and
the real issuer is only known from the token's own tenant id. Substituting it is safe **because**
the tenant is then checked against your list.

### Any other OpenID Connect provider

One extra line — the issuer. Endpoints and keys come from its discovery document.

```php
'keycloak' => [
    'issuer'        => 'https://id.example.com/realms/main',
    'client_id'     => …,
    'client_secret' => …,
],
```

### GitHub, and other providers without OpenID Connect

```php
'github' => [
    'client_id'     => $_ENV['GITHUB_CLIENT_ID'],
    'client_secret' => $_ENV['GITHUB_CLIENT_SECRET'],
],
```

GitHub has no discovery document and issues no ID token, so its endpoints are named in the
preset rather than read from it. Its quirks are handled for you: the credentials go where GitHub
documents them, its API version header is sent, and an address the person has not made public is
fetched from their verified address list instead of coming back empty.

**Naming a profile endpoint does not make a provider plain OAuth2.** Protocol and profile are
separate: give an OpenID Connect provider a `userinfo_url` and it stays OpenID Connect — the ID
token is verified first, the profile is fetched afterwards, and it is only accepted if it
describes the same subject. It adds to a verified identity; it never establishes one.

A provider is plain OAuth2 when it has no issuer. Such a provider takes three URLs and, if it
does not call its identifier `sub`, the field that holds it:

```php
'acme' => [
    'client_id'     => …,
    'client_secret' => …,
    'authorize_url' => 'https://acme.test/oauth/authorize',
    'token_url'     => 'https://acme.test/oauth/token',
    'userinfo_url'  => 'https://acme.test/api/me',
    'subject_field' => 'user_id',
],
```

**GitLab needs none of this** — it publishes an OpenID Connect discovery document, so
`'issuer' => 'https://gitlab.com'` is the whole configuration.

#### Two trust paths, and the difference between them

With OpenID Connect the provider signs a statement addressed to this application, and both the
signature and the address are verified. Without it there is nothing to sign: the identity comes
from an authenticated call to the provider's API with the access token just exchanged for the
code.

For the authorization-code flow that is sound — the token was minted for this client id, against
this redirect URI, with this PKCE verifier, so no token from anywhere else can reach that call.
It is weaker in kind rather than in strength: there is no audience-bound assertion to re-check
later, and nothing binds the answer to this particular login beyond the token itself. That is
also why no `nonce` is sent to such a provider — there would be nothing to bind it to.

One consequence worth knowing: a plain-OAuth2 provider states no issuer, so identities are filed
under `oauth:<provider key>`. **Renaming the key in your configuration detaches existing links.**
With OpenID Connect the issuer is the provider's own and renaming is harmless.

### When a provider rotates your client secret

Change the one line and deploy. Nothing else moves: the `client_id` stays, the callback URL stays,
every account link stays, and nobody is signed out. A client secret is only ever used at the token
endpoint, between your server and theirs — it never reaches a browser and never identifies anyone.

There is nothing to clear either. The secret is read from the configuration on the request that
needs it; what gets cached is discovery documents and signing keys, and neither contains it.

The awkward part is that two sides have to change and they cannot do it in the same instant. A
provider worth using holds both for a while — a `naf/oauth-server` does:

```bash
# on the server
vendor/bin/nix oauth:client:rotate-secret <client-id>
```

Deploy the new value here before that window closes; when it lapses, the old secret simply stops
being accepted and nothing has to run for that to happen. After a leak the server's `--now` ends
it immediately, and this application stops authenticating until the new secret is deployed — which
is the point, not a side effect.

### Check it before anybody tries

```bash
vendor/bin/nix oauth:doctor
```

It verifies the dependencies, the public URL, the user model and its contract, the link table,
and every configured login — including whether the provider's metadata is reachable and belongs
to the issuer you configured. It prints the callback URL to register, and never prints a secret.

### The older configuration

`oauth:providers` is the previous spelling of `auth:logins` and still works; it is used when
`auth:logins` is absent, and the error messages then name the keys you actually wrote.
`auth:providers` likewise still names account sources explicitly. Nothing has to be migrated.

### Everything else has a default

`callback_url`, `scope`, `label`, `after_login`, `error_route`, the table name and the cache
location are derived or defaulted. Set them when you actually need something else.

---

## The button

```php
use function Naf\OAuth\Client\oauth_button;
```

```php
<?= oauth_button('google') ?>                          <!-- "Mit Google anmelden" -->
<?= oauth_button('google', 'Continue with Google') ?>  <!-- explicit text wins -->
<?= oauth_button('google', next: '/projects/7') ?>     <!-- land there afterwards -->
```

The wording is settled highest-first: what you pass in, then your own
`oauth/button.phtml` in the application's view directory, then
`oauth:providers:<key>:label`, then the provider's own name. Copy the shipped view to change
the markup — yours wins, and nothing in the central configuration has to change for it.

A label is only ever a label. It never reaches an issuer, a client id, a redirect URI or a
subject.

---

## The routes

Shipped, named, and off with `'oauth' => ['routes' => false]`:

| | |
| --- | --- |
| `GET /auth/{provider}` | start a login |
| `GET /auth/{provider}/callback` | what the provider sends back |
| `GET /auth/{provider}/connect` | attach this provider to the account already signed in |

All three take `?next=/somewhere` — always a local path. Anything else falls back to
`oauth:after_login`, and "anything else" includes embedded control characters: browsers strip
tabs and newlines while normalising a URL, so `/\r//evil.test` would otherwise arrive as
`//evil.test`.

A provider reporting a failure is treated like any other answer: its `state` is checked and
consumed. A cancelled login therefore ends rather than sitting pending until it expires, and
nobody can drive the callback by appending `?error=` to it.

A refused login redirects to `oauth:error_route` with the reason flashed into the session as
`oauth_error`, rather than raising an error page. A cancelled login is something a person did,
not a server fault:

```php
<?php if ($reason = session()->getFlash('oauth_error')): ?>
    <p><?= $reason === 'not_linked'
        ? 'No account is linked to that login yet.'
        : 'That login could not be completed.' ?></p>
<?php endif ?>
```

---

## Which account is this?

The one decision left to you. Three answers are possible and only one is safe by default:

- **somebody linked it before** → that account is signed in. Nothing to write.
- **nobody did, and you allow it** → you create the account, the link is written, they are
  signed in.
- **nobody did** → refused with `not_linked`, so they can sign in normally and connect it.

Turning on the middle one is one setting and one function:

```php
'oauth' => ['accounts' => [
    'auto_register' => true,
    'create' => static fn(ExternalIdentity $external) => $users->create([
        'email' => $external->email,
        'name'  => $external->name,
    ]),
]],
```

With several account sources registered in `auth:providers`, name the one that owns external
logins in `oauth:accounts:provider`. With one, it is used without being named.

### Two rules it enforces for you

**Identities are keyed on `(issuer, subject)`, never on `subject` alone.** A subject is only
unique within its issuer; two providers can hand you the same string. The link table's primary
key *is* that pair, so two simultaneous first logins cannot both create a link.

**Creating an account and linking it are one act.** They run in one transaction, so a failed
link takes the half-made account with it — otherwise every retry leaves another orphan beside
the last one. The new account is then read back through the configured source before it signs
in: what signs in has to be what the next request will load, and the source is what decides who
may sign in at all.

**A matching e-mail address is never a link.** Not even a verified one: anybody who can get a
provider to assert an address could then walk into the account that uses it. Attaching a second
provider is a separate act, performed by somebody already signed in — and the person who
finishes it must be the person who started it:

```php
<a href="<?= route('oauth.connect', ['provider' => 'github']) ?>">Connect GitHub</a>
```

---

## Doing it yourself

Nothing above is mandatory. `oauth()` gives you the same flow with none of the routing:

```php
use function Naf\Auth\auth;
use function Naf\OAuth\Client\oauth;

return redirect(oauth('google')->authorizationUrl());

$callback = oauth('google')->callback();   // throws unless everything verifies
$external = $callback->identity;

$user = $yourAccounts->findBySubject($external->issuer, $external->subject)
    ?? throw new RuntimeException('Not linked.');

auth()->setIdentity($user, 'database');

return redirect($callback->redirectTo);
```

Writing the callback yourself means storing provider tokens yourself too — the shipped route calls
`Tokens::remember($callback)` after the sign-in has succeeded, and nothing else does. Keep that
order: a callback nobody is allowed to finish must not leave a working credential behind.

---

## Several tabs

Logins are keyed by their own `state`, so a person with three tabs open finishes all three.
Each entry is consumed on use and expires after ten minutes, which is also what makes a
replayed callback fail.

---

## What comes back

`Callback`: `identity`, `purpose` (`LOGIN` or `LINK`), `initiator`, `redirectTo`, `token`.

`ExternalIdentity`: `provider`, `issuer`, `subject`, `claims`, and `email` / `emailVerified` /
`name` for convenience. `emailVerified` is true only for a literal `true` — providers have sent
`"true"`, `1` and `"1"` there.

---

## Calling the provider afterwards

A login needs none of this. The identity is checked once and your own session is the authority
from then on, which is why signing in stores no provider tokens at all.

It is a different question when the application has to *act* at the provider — read somebody's
calendar, list their repositories, post on their behalf. That needs what the provider issued, kept
between visits, and still working an hour later.

```php
// app/config.php
'oauth' => [
    'tokens' => [
        'store' => true,
        'key'   => 'BASE64_OF_32_RANDOM_BYTES',
    ],
],
```

`nix oauth:doctor` says how to generate the key; it deliberately does not print one. Everything in
`oauth_provider_tokens` is encrypted with it, so a copy of the database is not a copy of anybody's
permissions — which is also why the key does not belong in that database. Losing it costs everybody
a new consent screen.

Then, wherever the API call happens:

```php
use function Naf\OAuth\Client\oauth;
use function Naf\OAuth\Client\oauth_token;

$token = oauth_token('google');

if ($token === null || !$token->grants('https://www.googleapis.com/auth/calendar.readonly')) {
    return redirect(oauth('google')->grantUrl(
        ['https://www.googleapis.com/auth/calendar.readonly'],
        auth()->providerName(),
        (string) auth()->id(),
    ));
}

$response = client()->get('https://www.googleapis.com/calendar/v3/calendars/primary/events', [
    'headers' => ['Authorization' => 'Bearer ' . $token->accessToken],
]);
```

`oauth_token()` hands out something usable or nothing: an expired access token is renewed on the
way out and the renewal written back. A provider that cannot be reached throws rather than
answering null, because an outage is not a withdrawn permission and must not send people through a
consent screen that cannot help.

### Without consent there is no access, and consent is not what you asked for

What the application may do is decided entirely by the scopes on the consent screen. Ask for
nothing beyond `openid email profile` — the default — and there is no API access at all.

Asking is not getting. RFC 6749 §5.1 obliges a provider to state the scope it actually issued
whenever it differs from the request, and Google lets people untick individual permissions. So
`$token->scope` is the granted scope, never the requested one, and `$token->grants(...)` is worth
asking before a call rather than after a 403 that will not explain itself.

### Ask when the feature is used, not at the login

`grantUrl()` exists so that extra permissions are requested at the moment they are needed. "Wants
to see your calendar" makes sense after somebody pressed a calendar button; at a login it reads as
a reason not to sign in. It returns through the ordinary callback, so there is no second route to
add.

A grant replaces the stored token with what the provider issued for it. Google is asked with
`include_granted_scopes`, so its answer carries the earlier permissions too; a provider that does
not do this issues a token for the new scope alone, and the previous one is gone.

### Two things that catch people out

**The refresh token arrives once.** Google returns it on the first consent and never again unless
consent is forced — `grantUrl()` forces it, the login does not. An installation that turns
`oauth:tokens:store` on *after* people have signed in has no refresh token for any of them until
they grant something again.

**Unlinking is not revoking.** Deleting the link only makes the application forget; the permission
stays listed in the person's account at the provider, looking current. `Tokens::forget()` tells the
provider first and then deletes, and belongs wherever an account is unlinked.

---

## When it does not verify

Every failure is an `OAuthException` carrying a short, stable `reason` alongside its message, so
an error page can tell a cancelled login from an expired one without matching on prose:

`provider_error`, `state_missing`, `state_unknown`, `code_missing`, `provider_mismatch`,
`token_request_failed`, `id_token_missing`, `id_token_invalid`, `nonce_mismatch`,
`issuer_mismatch`, `audience_mismatch`, `tenant_not_allowed`, `subject_missing`, `no_keys`,
`metadata_unavailable`, `no_session`, `access_token_missing`, `userinfo_unavailable`,
`subject_mismatch`, `not_linked`, `already_linked`, `initiator_mismatch`, `no_initiator`,
`account_unavailable`, `registration_refused`, `consent_required`, `refresh_failed`, `no_scopes`.

`already_linked` means exactly that — an integrity violation and nothing else. A dropped
connection or a value too long for its column surfaces as the database error it is, rather than
hiding a broken installation behind a message that sounds like ordinary use.

A misconfiguration raises `ConfigurationException` instead, and is left to surface the way every
other bug in your application does — it is addressed to you, not to a visitor.

---

## Provider metadata

Discovery documents and signing keys are cached under `storage/oauth` for a day, so a login
costs no extra request. A token signed with a key id we have not seen reloads the key set once —
which is what a rotation looks like from here — and a cooldown keeps invented key ids from
turning into a stream of outbound requests. A failed reload keeps using what is cached and backs off before trying again, so a provider that
is down does not turn every login into another outbound request. It never degrades into
accepting an unverified token — and it does not lean on stale metadata forever either: once the
cache has been expired for a day without the provider answering, logins fail with something an
operator can act on.

---

## What this is not

**There is no LDAP adapter here.** Names like `ldap` appear in tests and in `naf/auth`'s
examples as stand-ins for "a second account source"; that is not support, and nothing in these
packages speaks LDAP.

What does exist is the part that matters for adding one: every way of signing in ends at the
same local contract, `UserInterface`. A directory bind would not be an OAuth provider and must
not be forced through a redirect flow — it verifies a password against a server and then hands
over a user, which is what `auth()->setIdentity()` is for. The protocol differs; what a
signed-in person is does not.

### Where credentials belong

| | |
| --- | --- |
| Local passwords | hashed, never recoverable — `PasswordHasher` |
| Directory passwords | verified against the directory, never stored locally |
| Provider secrets, bind accounts | server-side configuration, out of the repository |
| Account links | stable external ids — `(issuer, subject)`, never an e-mail address |
| Your own tokens | the token store, as hashes |
| Providers' refresh tokens | only when you actually call their APIs — `oauth_provider_tokens`, encrypted with `oauth:tokens:key` |
| Your own client secrets | server-side configuration; rotated by changing one line, see above |

---

## A known limit

Taking a pending login out of the session is read-modify-write, and what makes that indivisible
is the session backend holding a lock for the request. PHP's own file handler does;
`naf/session`'s database handler does not. Two callbacks arriving for the same `state` in the
same instant could therefore both find it there.

Every check after that still applies — the authorization code is single-use at the provider, and
the ID token still has to verify — so this narrows the replay guarantee rather than opening a way
through it. A locking session backend closes it.

---

## Not here yet

- **Rotating `oauth:tokens:key`.** Changing it makes every stored grant unreadable, and everybody
  affected has to grant access again. Re-encrypting in place would need both keys held at once.

---

## Development

```bash
composer install
composer test
composer analyse
```

**A command is tested by running it.** `Tests\CommandTestCase` builds an application, boots the
plugin into it and executes the command against it, supplying only the two things a test cannot
have: a provider that answers without a network, and a database in memory. Nothing else is
mocked — which is the point, because the defects these commands actually had were not in any
class they call. They read the configuration from somewhere the application does not, printed a
URL the application would never send, and advised a migration that had already run. Every one of
those is invisible from below and obvious from here, so add a case to
`DiscoverCommandTest`/`DoctorCommandTest` when you touch either.

Adding one looks like this:

```php
final class SomeCommandTest extends CommandTestCase
{
    public function testItSaysWhatItDid(): void
    {
        $this->provider();                       // answers discovery and JWKS, no network
        $this->database();                       // the link and token tables, in memory
        $this->configure(auth: ['session' => false, 'logins' => [
            'acme' => ['issuer' => 'https://id.example.test', 'client_id' => 'abc'],
        ]]);
        $this->boot();

        $result = $this->execute(new DiscoverCommand(), ['acme']);

        $this->assertSucceeded($result);         // or assertFailed()
        self::assertSame('https://id.example.test', $result->value('Issuer'));
    }
}
```

`configure()` replaces the whole configuration rather than merging into the shipped one, which is
deliberate: a default that only ever arrives from `src/config.php` and disagrees with the one in
`bootstrap.php` shows up here and nowhere else. `CommandResult` carries the exit status and the
printed output with the colour stripped — `line($label)` finds a row, `value($label)` returns what
follows the label, `lines()` gives the lot.

The metadata cache goes to a temporary directory rather than into the repository, and every
service the plugin registers is reset between tests, so a case cannot pass on what the one before
it left behind.

CI covers PHP 8.3, 8.4 and 8.5.

---

## License

MIT License.
