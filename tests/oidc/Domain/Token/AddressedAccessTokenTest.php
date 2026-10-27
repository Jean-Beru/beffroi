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
 * Architecture §4.6 (issues #870 and #880): what the access token of a response needs from outside the provider,
 * the key of the tenant it is signed with and the kind of "sub" its client registered, opened before it is struck.
 */
final class AddressedAccessTokenTest extends TestCase
{
    /**
     * RFC 9068 §2.1: a token of a shape that signs is signed with the key that was opened for it.
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

    /**
     * A token of a shape that signs nothing is a reference to a record of the provider, signed with no key,
     * and asking it for one is a fault of the caller.
     */
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
     * OIDC Core §8 (issue #880): a token that names the person in it does so by the kind of "sub" that was opened
     * for it.
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

    /**
     * A token of a shape that names nobody in it was opened no kind of "sub", and asking it for one is a fault of
     * the caller.
     */
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
