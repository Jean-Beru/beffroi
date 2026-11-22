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
 * Decision 0018
 */
final class KeyManagementPanelTest extends BrowserTestCase
{
    protected static function kernelOptions(): array
    {
        return [
            'debug' => true,
        ];
    }

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
     * Decision 0018
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
