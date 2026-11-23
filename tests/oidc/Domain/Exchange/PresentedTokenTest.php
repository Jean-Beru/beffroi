<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Exchange;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8693 §2.1
 */
final class PresentedTokenTest extends TestCase
{
    /**
     * RFC 8693 §2.1
     */
    #[Test]
    #[DataProvider('provideTokensThatNameAPerson')]
    public function aTokenThatNamesAPersonIsAboutAUser(PresentedToken $token): void
    {
        // When / Then
        static::assertTrue($token->isAboutAUser());
    }

    /**
     * @return iterable<string, array{PresentedToken}>
     */
    public static function provideTokensThatNameAPerson(): iterable
    {
        $tenant = Fixtures::tenant();
        $client = Clients::confidential($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $session = Fixtures::session(Fixtures::user($tenant));

        yield 'somebody signed in for it' => [Tokens::presented($client, $session->user->subject, $session)];
        yield 'a client named its subject, nobody signing in (RFC 7523 §2.1)' => [
            Tokens::presented($client, $session->user->subject, person: $session->user->subject),
        ];
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function aTokenAClientHoldsForItselfIsAboutNoUser(): void
    {
        // Given
        $token = Tokens::presented(Clients::service(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET)), new Subject('batch'));

        // When / Then
        static::assertFalse($token->isAboutAUser());
    }

    /**
     * RFC 8693 §2.1, RFC 6749 §4.4
     */
    #[Test]
    public function aTokenItsClientHoldsUnderItsOwnNameForNobodyIsHeldForItself(): void
    {
        // Given
        $gateway = Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));
        $token = Tokens::presented($gateway, new Subject('gateway'));

        // When / Then
        static::assertTrue($token->isHeldForItselfBy($gateway));
    }

    /**
     * RFC 8693 §2.1, §4.1
     */
    #[Test]
    #[DataProvider('provideTokensAClientDoesNotHoldForItself')]
    public function aTokenOfAnotherClientOrAboutSomebodyElseIsNotHeldForItself(PresentedToken $token): void
    {
        // Given
        $gateway = Clients::gateway(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertFalse($token->isHeldForItselfBy($gateway));
    }

    /**
     * @return iterable<string, array{PresentedToken}>
     */
    public static function provideTokensAClientDoesNotHoldForItself(): iterable
    {
        $tenant = Fixtures::tenant();
        $hash = new FakePasswordHasher()->hash(Clients::SECRET);
        $gateway = Clients::gateway($tenant, $hash);
        $batch = Clients::service($tenant, $hash, 'batch');
        $session = Fixtures::session(Fixtures::user($tenant));

        yield 'held by another client, under the name of that client' => [Tokens::presented($batch, new Subject('batch'))];
        yield 'held by another client, under the name of the client' => [Tokens::presented($batch, new Subject('gateway'))];
        yield 'held by the client, under the name of another client' => [Tokens::presented($gateway, new Subject('batch'))];
        yield 'held by the client for a person somebody signed in for' => [Tokens::presented($gateway, $session->user->subject, $session)];
        yield 'held by the client for a person a client named (RFC 7523 §2.1)' => [
            Tokens::presented($gateway, $session->user->subject, person: $session->user->subject),
        ];
        yield 'held by the client under its own name, for a person' => [Tokens::presented($gateway, new Subject('gateway'), person: $session->user->subject)];
    }
}
