<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\PushedAuthorization;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class PushedAuthorizationRecordTest extends TestCase
{
    private const string NOW = '2026-09-22T12:00:00+00:00';

    private Tenant $tenant;

    private Client $client;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::confidential($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
    }

    /**
     * RFC 9126 §2.2: the record is bound to the client that pushed it, and a store keeps the name of
     * that client beside the tenant it belongs to.
     */
    #[Test]
    public function itTakesItsTenantAndItsClientNameFromItsClient(): void
    {
        // When
        $request = $this->request();

        // Then
        static::assertSame($this->tenant, $request->tenant);
        static::assertSame('oidc-demo', $request->clientId);
        static::assertFalse($request->isUsed());
    }

    #[Test]
    #[DataProvider('provideMalformedHashes')]
    public function itRefusesAReferenceThatIsNotStoredAsItsHash(string $hash): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A pushed authorization request is stored as the hex SHA-256 of its request URI.');

        // When
        $this->request(requestUriHash: $hash);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedHashes(): iterable
    {
        yield 'empty' => [''];
        yield 'the value itself' => [RequestUri::URN_PREFIX . str_repeat('a', 43)];
        yield 'too short' => [str_repeat('a', 63)];
        yield 'uppercase hex' => [str_repeat('A', 64)];
        yield 'not hex' => [str_repeat('z', 64)];
    }

    #[Test]
    public function itRefusesALifetimeThatEndsBeforeItBegins(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A pushed authorization request expires after it was pushed.');

        // When
        $this->request(expiresAt: new DateTimeImmutable(self::NOW));
    }

    /**
     * RFC 9126 §2.2: "expires_in" is the seconds the reference still has.
     */
    #[Test]
    public function itAnswersTheSecondsItStillHas(): void
    {
        // Given
        $request = $this->request();

        // When / Then
        static::assertSame(60, $request->expiresIn(new DateTimeImmutable(self::NOW)));
    }

    /**
     * RFC 9126 §2.2 asks for a positive integer; a record read after its lifetime is refused elsewhere,
     * and never described as already gone.
     */
    #[Test]
    public function theSecondsItStillHasAreNeverBelowOne(): void
    {
        // Given
        $request = $this->request();

        // When / Then
        static::assertSame(1, $request->expiresIn(new DateTimeImmutable('2026-09-22T12:05:00+00:00')));
    }

    /**
     * RFC 9126 §4: one use.
     */
    #[Test]
    public function consumingItMarksItUsed(): void
    {
        // Given
        $request = $this->request();
        $now = new DateTimeImmutable('2026-09-22T12:00:30+00:00');

        // When
        $request->consume($now);

        // Then
        static::assertTrue($request->isUsed());
        static::assertSame($now, $request->usedAt);
    }

    /**
     * The repository claims the record and calls consume() on the winner alone; calling it twice is a
     * programming error and not the replay of a reference.
     */
    #[Test]
    public function consumingItTwiceIsAProgrammingError(): void
    {
        // Given
        $request = $this->request();
        $request->consume(new DateTimeImmutable(self::NOW));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A pushed authorization request is consumed once; the authorization endpoint checks isUsed() first.');

        // When
        $request->consume(new DateTimeImmutable(self::NOW));
    }

    /**
     * A repository whose claim was lost writes the instant the store holds into its copy.
     */
    #[Test]
    public function itRecordsTheConsumptionTheStoreHolds(): void
    {
        // Given
        $request = $this->request();
        $winner = new DateTimeImmutable('2026-09-22T12:00:10+00:00');

        // When
        $request->recordConsumption($winner);

        // Then
        static::assertSame($winner, $request->usedAt);
    }

    /**
     * RFC 9126 §4: "An expired request_uri MUST be rejected as invalid", the instant it expires included.
     */
    #[Test]
    #[DataProvider('provideInstants')]
    public function itIsExpiredFromTheInstantItExpires(string $instant, bool $expired): void
    {
        // Given
        $request = $this->request();

        // When / Then
        static::assertSame($expired, $request->isExpired(new DateTimeImmutable($instant)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideInstants(): iterable
    {
        yield 'a second before' => ['2026-09-22T12:00:59+00:00', false];
        yield 'the very instant' => ['2026-09-22T12:01:00+00:00', true];
        yield 'a second after' => ['2026-09-22T12:01:01+00:00', true];
    }

    /**
     * RFC 9126 §2.2: the reference is bound to the client that posted it.
     */
    #[Test]
    public function itBelongsToTheClientThatPushedItAndToNoOther(): void
    {
        // Given
        $request = $this->request();

        // When / Then
        static::assertTrue($request->belongsTo($this->client));
        static::assertFalse($request->belongsTo(Clients::public($this->tenant)));
    }

    /**
     * A client of the same name in another tenant is another client.
     */
    #[Test]
    public function itBelongsToNoClientOfAnotherTenant(): void
    {
        // Given
        $request = $this->request();

        // When / Then
        static::assertFalse($request->belongsTo(Clients::confidential(
            Fixtures::tenant('other', 'https://id.other.example'),
            new FakePasswordHasher()->hash(Clients::SECRET),
        )));
    }

    /**
     * @param array<string, string> $parameters
     */
    private function request(?string $requestUriHash = null, ?DateTimeImmutable $expiresAt = null, array $parameters = []): PushedAuthorizationRecord
    {
        return new PushedAuthorizationRecord(
            $requestUriHash ?? RequestUri::of(Secrets::draw())->hash(),
            $this->client,
            $parameters,
            new DateTimeImmutable(self::NOW),
            $expiresAt ?? new DateTimeImmutable('2026-09-22T12:01:00+00:00'),
        );
    }
}
