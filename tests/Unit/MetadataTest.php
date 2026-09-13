<?php

declare(strict_types=1);

namespace Tests\Unit;

use NixPHP\OAuth\Client\Core\Metadata;
use NixPHP\OAuth\Client\Exception\OAuthException;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\FakeHttp;

/** Provider metadata is fetched rarely, reloaded deliberately, and never silently lost. */
final class MetadataTest extends TestCase
{
    private const string URL = 'https://id.example.test/jwks';

    private FakeHttp $http;
    private Metadata $metadata;
    private string $cache;

    protected function setUp(): void
    {
        $this->cache    = sys_get_temp_dir() . '/nixphp-oauth-meta-' . bin2hex(random_bytes(6));
        $this->http     = new FakeHttp();
        $this->metadata = new Metadata($this->http, $this->cache);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->cache . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->cache);
    }

    public function testItIsFetchedOnceAndThenServedFromDisk(): void
    {
        $this->http->on('GET', self::URL, ['keys' => ['first']]);

        self::assertSame(['keys' => ['first']], $this->metadata->jwks(self::URL));
        self::assertSame(['keys' => ['first']], $this->metadata->jwks(self::URL));
        self::assertSame(['keys' => ['first']], (new Metadata($this->http, $this->cache))->jwks(self::URL));

        self::assertSame(1, $this->http->calls('GET', self::URL), 'no request per login');
    }

    public function testAForcedReloadActuallyReloads(): void
    {
        $this->http->on('GET', self::URL, ['keys' => ['first']]);
        $this->metadata->jwks(self::URL);

        $this->http->on('GET', self::URL, ['keys' => ['rotated']]);

        self::assertSame(['keys' => ['rotated']], $this->metadata->jwks(self::URL, refresh: true));
        self::assertSame(2, $this->http->calls('GET', self::URL));
    }

    public function testForcedReloadsAreRateLimited(): void
    {
        $this->http->on('GET', self::URL, ['keys' => ['first']]);
        $this->metadata->jwks(self::URL);
        $this->metadata->jwks(self::URL, refresh: true);

        $this->http->on('GET', self::URL, ['keys' => ['never asked for']]);

        // A stream of tokens naming invented key ids must not become a stream of
        // outbound requests.
        self::assertSame(['keys' => ['first']], $this->metadata->jwks(self::URL, refresh: true));
        self::assertSame(2, $this->http->calls('GET', self::URL));
    }

    public function testAnUnreachableProviderFallsBackToWhatWeHave(): void
    {
        $this->http->on('GET', self::URL, ['keys' => ['first']]);
        $this->metadata->jwks(self::URL);

        $this->http->on('GET', self::URL, 'gateway timeout', 504);

        // Stale keys are a smaller problem than no keys: no keys would mean either
        // an outage or, far worse, a login nobody verified.
        self::assertSame(['keys' => ['first']], $this->metadata->jwks(self::URL, refresh: true));
    }

    public function testWithNothingCachedAFailureIsAFailure(): void
    {
        $this->http->on('GET', self::URL, 'nope', 500);

        try {
            $this->metadata->jwks(self::URL);
            self::fail('Expected an OAuthException.');
        } catch (OAuthException $e) {
            self::assertSame('metadata_unavailable', $e->reason);
        }
    }

    public function testAnAnswerThatIsNotJsonIsNotMetadata(): void
    {
        $this->http->on('GET', self::URL, '<html>sign in to the proxy</html>');

        try {
            $this->metadata->jwks(self::URL);
            self::fail('Expected an OAuthException.');
        } catch (OAuthException $e) {
            self::assertSame('metadata_unavailable', $e->reason);
        }
    }

    public function testTheCacheIsNotWorldReadable(): void
    {
        $this->http->on('GET', self::URL, ['keys' => ['first']]);
        $this->metadata->jwks(self::URL);

        $files = glob($this->cache . '/*.json') ?: [];

        self::assertCount(1, $files);
        self::assertSame('0600', substr(sprintf('%o', fileperms($files[0])), -4));
    }
}
