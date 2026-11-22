<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Exchange;

use function array_map;
use Beffroi\Oidc\Application\Exchange\PresentedTokenTypes;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\FakePresentedTokenType;
use Beffroi\Oidc\Tests\Fixture\TokenTypes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8693 §3
 */
final class PresentedTokenTypesTest extends TestCase
{
    /**
     * RFC 8693 §3
     */
    #[Test]
    public function itFindsTheTypeThatAnswersToAnIdentifier(): void
    {
        // Given
        $types = TokenTypes::served();

        // When
        $type = $types->named(TokenTypeIdentifier::ACCESS_TOKEN);

        // Then
        static::assertTrue($type?->identifier()->equals(TokenTypes::accessToken()));
    }

    #[Test]
    public function itFindsNothingForATypeTheProviderDoesNotRead(): void
    {
        // When / Then
        static::assertNull(TokenTypes::served()->named(TokenTypes::invented()->value));
    }

    /**
     * RFC 8693 §3
     */
    #[Test]
    public function itNamesTheTypesItIsWiredWithInTheOrderTheyAreWired(): void
    {
        // Given
        $types = new PresentedTokenTypes([
            new FakePresentedTokenType(TokenTypes::invented()),
            new FakePresentedTokenType(TokenTypes::accessToken()),
        ]);

        // When
        $identifiers = array_map(static fn (TokenTypeIdentifier $type): string => $type->value, $types->presentedTokenTypes());

        // Then
        static::assertSame([TokenTypes::invented()->value, TokenTypeIdentifier::ACCESS_TOKEN], $identifiers);
    }

    #[Test]
    public function itRefusesATypeWiredTwice(): void
    {
        // Given
        $types = new PresentedTokenTypes([
            new FakePresentedTokenType(TokenTypes::accessToken()),
            new FakePresentedTokenType(TokenTypes::accessToken()),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token type "urn:ietf:params:oauth:token-type:access_token" is wired twice.');

        // When
        $types->presentedTokenTypes();
    }

    /**
     * RFC 8693 §3
     */
    #[Test]
    public function itRefusesAnExchangeWiredWithNoType(): void
    {
        // Given
        $types = new PresentedTokenTypes([]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The token exchange reads at least one type of token (RFC 8693 section 3).');

        // When
        $types->presentedTokenTypes();
    }
}
