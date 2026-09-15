<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AccessTokenTest extends TestCase
{
    /**
     * RFC 6749 §5.1: "expires_in" is the lifetime in seconds from issuance.
     */
    #[Test]
    public function itKnowsItsLifetimeInSeconds(): void
    {
        $token = new AccessToken('at.value', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        static::assertSame('at.value', $token->value);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
        static::assertSame(600, $token->expiresIn());
        static::assertSame(1, new AccessToken('at.value', Fixtures::now(), Fixtures::now()->modify('+1 second'))->expiresIn());
    }

    #[Test]
    public function itRefusesAnEmptyValue(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AccessToken('', Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * A token that expires within the second it was issued would advertise "expires_in": 0.
     */
    #[Test]
    public function itRefusesToExpireWithinTheSecondItWasIssued(): void
    {
        foreach ([Fixtures::now(), Fixtures::now()->modify('+500 milliseconds'), Fixtures::now()->modify('-1 second')] as $expiresAt) {
            try {
                new AccessToken('at.value', Fixtures::now(), $expiresAt);
                static::fail('The token should have been refused.');
            } catch (InvalidArgumentException $exception) {
                static::assertStringContainsString('one second', $exception->getMessage());
            }
        }
    }
}
