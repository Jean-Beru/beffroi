<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Oidc\Application\Claims\OpenedPublicSubjectIdentifier;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Exception\LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §4.6
 */
final class AddressedAccessTokenTest extends TestCase
{
    /**
     * RFC 9068 §2.1
     */
    #[Test]
    public function aTokenOfAShapeThatSignsIsSignedWithTheKeyItWasGiven(): void
    {
        // Given
        $key = Keys::openedSigningKey(Fixtures::tenant());

        // When
        $addressed = new AddressedAccessToken($key);

        // Then
        static::assertSame($key, $addressed->signingKey());
    }

    #[Test]
    public function aTokenOfAShapeThatSignsNothingIsSignedWithNoKey(): void
    {
        // Given
        $addressed = new AddressedAccessToken();

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('An access token whose shape signs nothing is signed with no key.');

        // When
        $addressed->signingKey();
    }

    /**
     * OIDC Core §8
     */
    #[Test]
    public function aTokenThatNamesThePersonDoesSoByTheKindItWasGiven(): void
    {
        // Given
        $subjectIdentifier = new OpenedPublicSubjectIdentifier();

        // When
        $addressed = new AddressedAccessToken(Keys::openedSigningKey(Fixtures::tenant()), subjectIdentifier: $subjectIdentifier);

        // Then
        static::assertSame($subjectIdentifier, $addressed->subjectIdentifier());
    }

    #[Test]
    public function aTokenOfAShapeThatNamesNobodyAssignsNoSubject(): void
    {
        // Given
        $addressed = new AddressedAccessToken();

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('An access token whose shape names nobody in it assigns no "sub".');

        // When
        $addressed->subjectIdentifier();
    }
}
