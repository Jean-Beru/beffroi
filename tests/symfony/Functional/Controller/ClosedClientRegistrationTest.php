<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0009
 */
final class ClosedClientRegistrationTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_REGISTRATION_MODE'] = '';
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_REGISTRATION_MODE'], $_ENV['BEFFROI_TEST_REGISTRATION_MODE']);
    }

    #[Test]
    public function aClosedTenantAnswersTheRegistrationEndpointLikeAnUnknownPath(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer a-value-nobody-was-handed',
            ],
            content: json_encode([
                'redirect_uris' => ['https://registered.test/callback'],
            ], JSON_THROW_ON_ERROR),
        );

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function aClosedTenantAnnouncesNoRegistrationEndpoint(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertArrayNotHasKey('registration_endpoint', self::json($this->browser->getResponse()));
    }
}
