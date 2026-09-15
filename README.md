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

## Documentation

**[Signing in with a provider →](https://nafphp.github.io/docs/oauth-client/)**

Everything about this package — what it does, how it is configured and what it needs — lives
in the [NAF documentation](https://nafphp.github.io/docs/). Not sure which packages you need?
[Start here](https://nafphp.github.io/docs/choosing-packages/).

## Install

```bash
composer require naf/oauth-client
```

## License

MIT. Part of [NAF](https://github.com/nafphp/framework).

## PHP code style

Source, tests and PHP templates follow the shared [NAF code style](https://github.com/nafphp/docs/blob/main/CODE_STYLE.md)
(PER Coding Style 3.0 with the Nafinity readability rules). After `composer install`, run
`composer style:check` to verify formatting or `composer style:fix` to apply it. The formatter
is a development dependency. Review template output and run the package checks after changes.
