<?php

declare(strict_types=1);

return [
    /*
     * The public base URL of this application, e.g. https://example.com.
     *
     * There is no trustworthy source for this inside a request: Host and the
     * X-Forwarded-* headers are set by whoever is calling. Every redirect URI is
     * derived from this one value, so it is stated once and never guessed.
     */
    'public_url' => null,

    'oauth' => [
        // Ship GET /auth/{provider} and GET /auth/{provider}/callback.
        'routes' => true,

        // Where a finished login lands. Always a local path.
        'after_login' => '/',

        // Where a refused login lands. The reason is flashed as 'oauth_error'.
        'error_route' => '/',

        // Provider key => settings. A known key (google, microsoft) needs nothing
        // but its credentials; anything else needs an issuer.
        'providers' => [],

        'accounts' => [
            // Which naf/auth source owns the local accounts. Null uses the only
            // registered one and asks for a name once there are several.
            'provider' => null,

            // Create an account for an external identity nobody is linked to yet.
            'auto_register' => false,

            // fn(ExternalIdentity): ?IdentityInterface — required when auto_register is on.
            'create' => null,

            // The link table. Its migration ships with naf/database installed.
            'table' => 'oauth_identities',
        ],

        /*
         * Keeping what the provider issues.
         *
         * A login needs none of this: the identity is checked once, and from then
         * on your own session is the authority. Turn it on only when the
         * application has to call the provider afterwards — read a calendar, list
         * repositories — and remember that it can only ever call what the person
         * agreed to on the consent screen.
         */
        'tokens' => [
            // Off by default. Storing a refresh token means holding a standing
            // permission to act as somebody, which is not something to acquire
            // by accident.
            'store' => false,

            /*
             * Base64 of 32 random bytes. Everything in the table is encrypted
             * with it, so a copy of the database is not enough to use a grant —
             * which means this key does not belong in the database, and losing
             * it costs everybody a new consent screen.
             *
             * "naf oauth:doctor" says how to generate one; it deliberately
             * does not print the key itself.
             */
            'key' => null,

            'table' => 'oauth_provider_tokens',
        ],

        // Discovery documents and signing keys live here.
        // Null resolves to BASE_PATH/storage/oauth.
        'cache_path' => null,
    ],
];
