<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use function json_decode;
use PHPUnit\Framework\Attributes\Test;

/**
 * Issue #911: what a deployment of the image chooses, it names by environment, and the image is not rebuilt
 * for it. A real environment variable wins over .env, as it does on a deployment, so the variables are named
 * before the kernel boots and given back after.
 */
final class ChoicesOfTheDeploymentTest extends BrowserTestCase
{
    private const array CHOICES = [
        'BEFFROI_REGISTRATION_MODE' => 'initial_access_token',
        'BEFFROI_TENANT_NAME' => 'Example Corporation',
        'BEFFROI_TENANT_LOGO_URI' => 'https://assets.example.com/mark.svg',
        'BEFFROI_TENANT_PRIMARY_COLOR' => '#0b5d1e',
        'BEFFROI_TENANT_PRIMARY_CONTENT_COLOR' => '#fafafa',
    ];

    /**
     * @var array<string, array{mixed, mixed}>
     */
    private array $before = [];

    protected function setUp(): void
    {
        foreach (self::CHOICES as $name => $value) {
            $this->before[$name] = [$_SERVER[$name] ?? null, $_ENV[$name] ?? null];
            $_SERVER[$name] = $value;
            $_ENV[$name] = $value;
        }
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach ($this->before as $name => [$server, $environment]) {
            $_SERVER[$name] = $server;
            $_ENV[$name] = $environment;
        }
    }

    /**
     * RFC 7591, decision 0009: the mode a deployment names is the registration endpoint its tenant announces,
     * which is how a client reaches an image that declares none.
     */
    #[Test]
    public function theTenantAnnouncesTheRegistrationEndpointOfTheModeItNames(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $document = json_decode(self::string($this->browser->getResponse()->getContent()), true);
        static::assertIsArray($document);
        static::assertSame('https://op.test/register', $document['registration_endpoint'] ?? null);
    }

    #[Test]
    public function aPageShowsTheMarkItNamesUnderTheNameItNames(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $logo = $this->accountHome()->filter('img[data-tenant="logo"]');

        // Then
        static::assertSame('https://assets.example.com/mark.svg', $logo->attr('src'));
        static::assertSame('Example Corporation', $logo->attr('alt'));
    }

    #[Test]
    public function aPageIsDrawnInTheColoursItNames(): void
    {
        // Given
        $this->signIn(self::user());

        // When
        $style = $this->accountHome()->filter('head style')->text();

        // Then
        static::assertStringContainsString('--color-primary: #0b5d1e; --color-primary-content: #fafafa;', $style);
    }
}
