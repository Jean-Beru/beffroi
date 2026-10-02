<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenAuthorization;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Tests\Fixture\Policies;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2, decision 0009: the mode built first. A registration is authorised by a token the tenant
 * issued, presented as a bearer credential, and spent in the same request.
 */
final class InitialAccessTokenAuthorizationTest extends TestCase
{
    private const string VALUE = 'a-value-the-tenant-handed-out';

    private InMemoryInitialAccessTokenRepository $tokens;

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->tenant = Fixtures::tenant();
    }

    /**
     * An initial access token says who may register, never what is registered: it puts nothing in front
     * of the members the client sent.
     */
    #[Test]
    public function aTokenOfTheTenantAuthorisesARegistrationAndAddsNothingToIt(): void
    {
        // Given
        $this->issue();

        // When
        $sources = $this->authorize(self::presenting(self::VALUE));

        // Then
        static::assertSame([], $sources);
    }

    /**
     * A token worth one registration registers one: what it was worth is spent in the request it
     * authorised.
     */
    #[Test]
    public function aTokenIsSpentByTheRegistrationItAuthorises(): void
    {
        // Given
        $token = $this->issue();

        // When
        $this->authorize(self::presenting(self::VALUE));

        // Then
        static::assertTrue($token->isSpent());
    }

    /**
     * Decision 0006: whoever does not hold a token of this tenant learns nothing about the one they
     * presented; the five refusals read the same.
     */
    #[Test]
    #[DataProvider('provideRefusedRequests')]
    public function aRequestThisProviderWillNotActOnIsRefusedTheSameWay(?string $header, bool $spent, bool $expired, bool $revoked): void
    {
        // Given
        $token = $this->issue();
        if ($spent) {
            $token->spend();
        }
        if ($revoked) {
            $token->revoke(Fixtures::now());
        }
        $now = $expired ? Fixtures::now()->modify('+2 days') : Fixtures::now();

        // Then
        $this->expectException(UnauthorizedRegistrationException::class);
        $this->expectExceptionMessageIs('invalid_token: The request does not carry an initial access token of this tenant (RFC 7591 section 1.2).');

        // When
        $this->authorize(new RegistrationRequest([], $header), $now);
    }

    /**
     * @return iterable<string, array{string|null, bool, bool, bool}>
     */
    public static function provideRefusedRequests(): iterable
    {
        yield 'no Authorization header at all' => [null, false, false, false];

        yield 'a header of another scheme' => ['Basic ' . self::VALUE, false, false, false];

        yield 'a value nobody was handed' => ['Bearer a-value-nobody-was-handed', false, false, false];

        yield 'a token already worth nothing' => ['Bearer ' . self::VALUE, true, false, false];

        yield 'a token that expired' => ['Bearer ' . self::VALUE, false, true, false];

        yield 'a token the tenant took back' => ['Bearer ' . self::VALUE, false, false, true];
    }

    /**
     * RFC 9110 §11.6.1: a scheme is compared without regard to case, so a client that spelled it its own
     * way is authorised all the same.
     */
    #[Test]
    public function theSchemeIsReadWithoutRegardToCase(): void
    {
        // Given
        $this->issue();

        // When
        $sources = $this->authorize(self::presenting(self::VALUE, 'bearer'));

        // Then
        static::assertSame([], $sources);
    }

    /**
     * The tokens of one tenant are no business of another: a token issued elsewhere opens nothing here.
     */
    #[Test]
    public function aTokenOfAnotherTenantAuthorisesNothing(): void
    {
        // Given
        $this->issue(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        $this->expectException(UnauthorizedRegistrationException::class);

        // When
        $this->authorize(self::presenting(self::VALUE));
    }

    private function issue(?Tenant $tenant = null): InitialAccessToken
    {
        $token = new InitialAccessToken(
            Uuid::v7(),
            $tenant ?? $this->tenant,
            DrawnSecret::digestOf(self::VALUE),
            'The team that integrates',
            1,
            Fixtures::now(),
            Fixtures::now()->modify('+1 day'),
        );
        $this->tokens->save($token);

        return $token;
    }

    /**
     * @return list<object>
     */
    private function authorize(RegistrationRequest $request, ?DateTimeImmutable $now = null): array
    {
        return new InitialAccessTokenAuthorization(
            $this->tokens,
            new MockClock($now ?? Fixtures::now()),
        )->authorize($this->tenant, $request, Policies::controlled());
    }

    private static function presenting(string $value, string $scheme = 'Bearer'): RegistrationRequest
    {
        return new RegistrationRequest([], $scheme . ' ' . $value);
    }
}
