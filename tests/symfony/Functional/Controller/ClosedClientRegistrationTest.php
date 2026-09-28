<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0009: closed is the default and closed is what a deployment that writes nothing gets. Such a
 * tenant has no registration endpoint rather than one that reads a request and refuses it: the document
 * says so by announcing none, and the endpoint says so with the 404 an unknown path gets.
 *
 * The mode of the tenant is read from the environment at runtime, the way the load budgets are, so that
 * a closed deployment is a kernel this test names before it boots one.
 */
final class ClosedClientRegistrationTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        $_SERVER['HEIDI_TEST_REGISTRATION_MODE'] = '';
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['HEIDI_TEST_REGISTRATION_MODE'], $_ENV['HEIDI_TEST_REGISTRATION_MODE']);
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
