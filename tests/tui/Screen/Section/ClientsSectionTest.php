<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function str_contains;

/**
 * The clients of the tenant, listed by their name, and what one of them registered once the administrator asks.
 */
final class ClientsSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function theClientsAreListedByTheirNameWithWhereTheyCameFrom(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [
                self::client('oidc-demo', 'The demonstration', 'configuration', '2026-11-04T10:00:00Z'),
                self::client('TS5oFb4MAr11', null, 'registration', null),
            ]],
        ]);

        // When
        $this->screen->open('section.clients');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 1], [
            preg_match('/The demonstration +oidc-demo +configuration .*2026-11-04 10:00/', $screen),
            preg_match('/- +TS5oFb4MAr11 +registration /', $screen),
        ]);
    }

    /**
     * Enter goes into the list, and Enter on a client reads what it registered, its identifier written as a segment
     * of the path (RFC 3986 §3.3).
     */
    #[Test]
    public function enterOnAClientReadsWhatItRegistered(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/clients' => ['clients' => [self::client('a client', 'A client', 'registration', null)]],
            '/clients/a%20client' => [
                ...self::client('a client', 'A client', 'registration', null),
                'administration' => true,
                'metadata' => [
                    'token_endpoint_auth_method' => 'private_key_jwt',
                    'redirect_uris' => ['http://127.0.0.1:8123/callback'],
                ],
            ],
        ]);
        $this->screen->open('section.clients');

        // When
        $this->screen->press(["\r", "\r"]);

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true, true], [
            str_contains($screen, 'What it registered'),
            str_contains($screen, 'private_key_jwt'),
            str_contains($screen, 'http://127.0.0.1:8123/callback'),
        ]);
    }

    /**
     * Decision 0009: a name a third party registered is shown, and the terminal is handed none of it as a sequence.
     */
    #[Test]
    public function aNameAThirdPartyRegisteredIsDrawnAsText(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => [self::client('evil', "Evil\e]0;owned\x07", 'registration', null)]]]);

        // When
        $this->screen->open('section.clients');

        // Then
        static::assertSame(
            [false, true],
            [str_contains($this->screen->terminal->getOutput(), "\e]0;owned"), str_contains($this->screen->screen(), 'Evil]0;owned')],
        );
    }

    #[Test]
    public function aTenantWithoutAClientIsSaidSo(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/clients' => ['clients' => []]]);

        // When
        $this->screen->open('section.clients');

        // Then
        static::assertStringContainsString('The tenant has no client.', $this->screen->screen());
    }

    /**
     * @return array<string, mixed>
     */
    private static function client(string $clientId, ?string $name, string $source, ?string $lastUsedAt): array
    {
        return [
            'client_id' => $clientId,
            'client_name' => $name,
            'source' => $source,
            'registered_at' => null,
            'last_used_at' => $lastUsedAt,
        ];
    }
}
