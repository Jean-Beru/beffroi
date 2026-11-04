<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use function array_map;
use function class_implements;
use function str_repeat;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8693 §2.1, RFC 7523 §2.1
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
     * Architecture §4.5
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
     * RFC 8707 §2
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
     * Architecture §4.6
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
     * @param list<string> $scopes
     * @param list<string> $granted
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
     * RFC 8693 §2.1, RFC 7523 §2.1
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
