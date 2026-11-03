<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Profiler;

use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use function sort;
use function sprintf;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Profiler\Profile;
use Symfony\Component\KeyManagement\DataCollector\KeyManagementDataCollector;

/**
 * The panel of `symfony/key-management` on a request that opened a sealed column (issue #427).
 *
 * The component traces what it builds itself and nothing else: the clients it is given, its own envelope
 * encrypter and its own store. This provider uses none of those three, composing a scope of its own over a
 * router of stores (decision 0018), so a page that sealed or opened a column reported "Nothing was
 * encrypted or decrypted" whatever it had done. The decorators are posed by the provider in debug.
 *
 * **What the panel must keep reporting as zero is the KMS.** A data key is unwrapped once per key and per
 * thread, so a request served by a thread that already holds it asks the KMS nothing, which is what
 * decision 0018 wants and what the third success criterion of the spike counts. A panel that showed a KMS
 * call per value would be reporting a defect, not an improvement.
 *
 * The kernel behind the browser is in debug, which is the one condition these decorators are wired under.
 */
final class KeyManagementPanelTest extends BrowserTestCase
{
    protected static function kernelOptions(): array
    {
        return [
            'debug' => true,
        ];
    }

    /**
     * A page of the account reads a user whose seventeen columns are sealed, so the store is asked for the
     * data key of the scope and the payloads are opened under it.
     */
    #[Test]
    public function aPageThatOpensASealedColumnIsReportedByThePanel(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', 'correct horse battery staple'));
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/account/profile');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        $collector = $this->collector();
        static::assertGreaterThan(0, $collector->getStoreCallCount());
        static::assertGreaterThan(0, $collector->getOperationCount());
    }

    /**
     * What the panel is for, and what the third success criterion of the spike counts: **one data key per
     * scope**, whatever the number of values opened under it. The panel groups its calls by scope, and
     * each scope of this page carries exactly one.
     *
     * The scopes themselves are readable there, `<slug>.<family>`, which is what decision 0018 made the
     * only channel between a sealed column and its store.
     */
    #[Test]
    public function thePanelGroupsTheCallsByScopeAndEachScopeCarriesOneDataKey(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', 'correct horse battery staple'));
        $this->browser->enableProfiler();

        // When
        $this->browser->request('GET', '/account/profile');

        // Then
        $scopes = [];
        foreach ($this->collector()->getKeys() as $key) {
            if (($key['kind'] ?? null) !== 'scope') {
                continue;
            }
            static::assertIsString($key['label']);
            static::assertIsArray($key['data_keys']);
            static::assertCount(1, $key['data_keys'], sprintf('the scope "%s" opened more than one data key.', $key['label']));
            $scopes[] = $key['label'];
        }
        sort($scopes);
        static::assertSame(['default.authentication_session', 'default.user'], $scopes);
    }

    private function collector(): KeyManagementDataCollector
    {
        $profile = $this->browser->getProfile();
        static::assertInstanceOf(Profile::class, $profile);
        $collector = $profile->getCollector('key_management');
        static::assertInstanceOf(KeyManagementDataCollector::class, $collector);

        return $collector;
    }
}
