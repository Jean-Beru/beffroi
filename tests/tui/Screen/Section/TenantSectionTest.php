<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function str_contains;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The tenant as the administration API says it, read once and again when the administrator asks.
 */
final class TenantSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function theTenantIsShownAsTheApiSaysIt(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant' => self::tenant()]);

        // When
        $this->screen->open('section.tenant');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, true, 1, true, true], [
            str_contains($screen, 'Beffroi Example'),
            str_contains($screen, '2026-10-01 08:00:00 UTC'),
            preg_match('/phr +phishing_resistant/', $screen),
            str_contains($screen, 'administrators, operators'),
            str_contains($screen, '180 days'),
        ]);
    }

    /**
     * What was read stays shown while another section is, and is read again when the administrator asks.
     */
    #[Test]
    public function theTenantIsReadAgainOnlyWhenTheAdministratorAsks(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/tenant' => self::tenant()]);
        $this->screen->open('section.tenant');
        $this->screen->press(["\e[B", "\e[A"]);

        // When
        $this->screen->press('r');

        // Then
        static::assertSame(2, $this->screen->requestsTo('/tenant'));
    }

    /**
     * RFC 6750 §3.1: a token the API no longer takes, which the session cannot refresh, is said with what to do.
     */
    #[Test]
    public function aTokenTheApiNoLongerTakesIsSaidWithWhatToDo(): void
    {
        // Given
        $this->screen = new SignedInScreen([
            '/tenant' => static fn (): MockResponse => new MockResponse('', [
                'http_code' => 401,
                'response_headers' => [
                    'WWW-Authenticate' => 'DPoP error="invalid_token", error_description="The access token expired."',
                ],
            ]),
        ]);

        // When
        $this->screen->open('section.tenant');

        // Then
        static::assertStringContainsString('The administration API no longer takes the tokens', $this->screen->screen());
    }

    /**
     * @return array<string, mixed>
     */
    private static function tenant(): array
    {
        return [
            'slug' => 'default',
            'issuer' => 'https://op.example',
            'name' => 'Beffroi Example',
            'created_at' => '2026-10-01T08:00:00Z',
            'login_floor' => 'any_proof',
            'authentication_classes' => [['acr' => 'phr', 'predicate' => 'phishing_resistant']],
            'administrators' => ['administrators', 'operators'],
            'administration_api' => 'https://admin.op.example',
            'journal_retention_days' => 180,
        ];
    }
}
