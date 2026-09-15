<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class RefreshTokenFamilyTest extends TestCase
{
    /**
     * Architecture §4.6: the family descends from a code and carries the absolute lifetime, ninety days,
     * the last instant excluded.
     */
    #[Test]
    public function itDescendsFromACodeAndExpiresAbsolutely(): void
    {
        $id = Uuid::v7();
        $family = new RefreshTokenFamily($id, AuthorizationCode::hash('the-code'), Fixtures::now(), Fixtures::now()->modify('+90 days'));

        static::assertSame($id, $family->id);
        static::assertSame(AuthorizationCode::hash('the-code'), $family->authorizationCodeHash);
        static::assertEquals(Fixtures::now(), $family->startedAt);
        static::assertFalse($family->isExpired(Fixtures::now()));
        static::assertFalse($family->isExpired(Fixtures::now()->modify('+90 days -1 second')));
        static::assertTrue($family->isExpired(Fixtures::now()->modify('+90 days')));
        static::assertTrue($family->equals(new RefreshTokenFamily($id, AuthorizationCode::hash('another'), Fixtures::now(), Fixtures::now()->modify('+1 day'))));
        static::assertFalse($family->equals(new RefreshTokenFamily(Uuid::v7(), AuthorizationCode::hash('the-code'), Fixtures::now(), Fixtures::now()->modify('+90 days'))));
    }

    #[Test]
    public function itRefusesACodeThatIsNotAHexSha256(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RefreshTokenFamily(Uuid::v7(), 'the-code', Fixtures::now(), Fixtures::now()->modify('+90 days'));
    }

    #[Test]
    public function itRefusesToExpireBeforeItStarted(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RefreshTokenFamily(Uuid::v7(), AuthorizationCode::hash('the-code'), Fixtures::now(), Fixtures::now());
    }
}
