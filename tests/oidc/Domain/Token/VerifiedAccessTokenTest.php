<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 9068 §4, Architecture §4.6
 */
final class VerifiedAccessTokenTest extends TestCase
{
    /**
     * RFC 6749 §4.4
     */
    #[Test]
    #[DataProvider('provideTokens')]
    public function itSaysWhetherItNamesAPerson(?TokenSignIn $signIn, ?Subject $person, bool $namesAPerson): void
    {
        // Given
        $token = new VerifiedAccessToken(
            Clients::public(Fixtures::tenant()),
            new TokenAudience([Clients::CALENDAR]),
            new Subject('alice-subject'),
            Uuid::v7(),
            new Scopes([new Scope('invoices.read')]),
            $signIn,
            [],
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
            person: $person,
        );

        // When / Then
        static::assertSame($namesAPerson, $token->namesAPerson());
    }

    /**
     * @return iterable<string, array{TokenSignIn|null, Subject|null, bool}>
     */
    public static function provideTokens(): iterable
    {
        yield 'somebody signed in for it' => [
            new TokenSignIn(Uuid::v7(), new AuthenticationSnapshot(Fixtures::now(), ['pwd'], '1')),
            null,
            true,
        ];
        yield 'it says who it is about, nobody having signed in for it here' => [null, new Subject('alice-subject'), true];
        yield 'a client holds it for itself' => [null, null, false];
    }
}
