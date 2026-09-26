<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use function array_map;
use function class_implements;
use function str_repeat;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Exchange\Actor;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\SubjectAuthorization;
use Heidi\Oidc\Domain\Token\TokenSignIn;
use Heidi\Oidc\Domain\Token\UserAuthorizationInterface;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * What a client is entitled to for a subject it did not sign in (RFC 8693 §2.1, RFC 7523 §2.1): the shape both
 * grants that read something as their input produce.
 */
final class SubjectAuthorizationTest extends TestCase
{
    private Tenant $tenant;

    private Client $gateway;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->gateway = Clients::gateway($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
    }

    /**
     * Architecture §4.5: nobody signed in here, so nothing of a session is invented and no document about a
     * user can be issued from it.
     */
    #[Test]
    public function itIsNotAnAuthorizationSomebodySignedInFor(): void
    {
        // When
        $authorization = $this->authorization();

        // Then
        static::assertNotContains(UserAuthorizationInterface::class, class_implements($authorization));
        static::assertTrue($authorization->tenant->equals($this->tenant));
        static::assertNull($authorization->signIn);
        static::assertNull($authorization->actor);
    }

    /**
     * RFC 8707 §2: the access token is addressed to the resources the request named.
     */
    #[Test]
    public function theTokenIsAddressedToTheResourcesTheRequestNamed(): void
    {
        // When
        $authorization = $this->authorization(resources: ResourceIndicators::of([Clients::CALENDAR]));

        // Then
        static::assertSame([Clients::CALENDAR], $authorization->audience()->values);
    }

    /**
     * Architecture §4.6: each kind of authorization writes the record of its own kind.
     */
    #[Test]
    public function itIsKeptAsTheRecordOfItsOwnKind(): void
    {
        // Given
        $session = Fixtures::session();
        $signIn = new TokenSignIn($session->id, AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()));
        $authorization = $this->authorization(signIn: $signIn);

        // When
        $record = $authorization->storedUnder(str_repeat('a', 64), Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // Then
        static::assertSame('alice-subject', $record->subject->value);
        static::assertTrue($record->signIn()?->sessionId->equals($session->id));
        static::assertSame([Clients::CALENDAR], $record->audience()->values);
    }

    /**
     * @param list<string> $scopes what the response carries
     * @param list<string> $granted what the presented token or the trusted issuer carried
     */
    #[Test]
    #[DataProvider('provideWhatCouldNotHaveBeenGranted')]
    public function itRefusesWhatTheClientCouldNotHaveBeenGranted(
        array $scopes,
        array $granted,
        string $resource,
        string $grantedResource,
        string $reason,
    ): void {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        $this->authorization(
            scopes: self::scopes($scopes),
            grantedScopes: self::scopes($granted),
            resources: ResourceIndicators::of([$resource]),
            grantedResources: ResourceIndicators::of([$grantedResource]),
        );
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, string, string, string}>
     */
    public static function provideWhatCouldNotHaveBeenGranted(): iterable
    {
        yield 'a scope wider than the granted ones' => [
            ['invoices.read', 'invoices.write'],
            ['invoices.read'],
            Clients::CALENDAR,
            Clients::CALENDAR,
            'among the granted ones (RFC 8693 section 2.1)',
        ];
        yield 'a scope the client did not register' => [
            ['openid'],
            ['openid'],
            Clients::CALENDAR,
            Clients::CALENDAR,
            'among the ones the client registered (RFC 6749 section 3.3)',
        ];
        yield 'a resource wider than the granted ones' => [
            ['invoices.read'],
            ['invoices.read'],
            Clients::CONTACTS,
            Clients::CALENDAR,
            'among the granted ones (RFC 8693 section 2.1)',
        ];
    }

    /**
     * RFC 8693 §2.1, RFC 7523 §2.1: both grants authenticate the client, so a public client cannot hold what
     * either of them hands out.
     */
    #[Test]
    public function aPublicClientIsRefusedOne(): void
    {
        // Given
        $public = Clients::public($this->tenant, resources: Clients::resources());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('granted to a client that authenticates itself');

        // When
        new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            $public,
            new Subject('alice-subject'),
            self::scopes(['openid']),
            self::scopes(['openid']),
            ResourceIndicators::of([Clients::CALENDAR]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
    }

    private function authorization(
        ?Scopes $scopes = null,
        ?Scopes $grantedScopes = null,
        ?ResourceIndicators $resources = null,
        ?ResourceIndicators $grantedResources = null,
        ?TokenSignIn $signIn = null,
        ?Actor $actor = null,
    ): SubjectAuthorization {
        return new SubjectAuthorization(
            Grants::tokenExchange(),
            Uuid::v7(),
            $this->gateway,
            new Subject('alice-subject'),
            $scopes ?? self::scopes(['invoices.read']),
            $grantedScopes ?? self::scopes(['invoices.read', 'invoices.write']),
            $resources ?? ResourceIndicators::of([Clients::CALENDAR]),
            $grantedResources ?? ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]),
            $signIn,
            $actor,
        );
    }

    /**
     * @param list<string> $values
     */
    private static function scopes(array $values): Scopes
    {
        return new Scopes(array_map(static fn (string $value): Scope => new Scope($value), $values));
    }
}
