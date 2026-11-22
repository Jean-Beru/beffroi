<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Registration;

use Beffroi\Oidc\Domain\Client\Registration\RegistrationErrorResponse;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\InvalidRedirectUriException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §3.2.2
 */
final class RegistrationErrorResponseTest extends TestCase
{
    #[Test]
    public function itAnswersWithTheCodeTheRefusalNamesAndWhatItSays(): void
    {
        // Given
        $exception = new InvalidRedirectUriException('redirect_uris', 'the registration the client sent', 'The URI carries a fragment.');

        // When
        $response = RegistrationErrorResponse::fromException($exception);

        // Then
        static::assertSame(
            [
                'error' => 'invalid_redirect_uri',
                'error_description' => 'The URI carries a fragment.',
            ],
            $response->parameters(),
        );
    }

    /**
     * RFC 7591 §3.2.2
     */
    #[Test]
    public function theSectionSignOfAMessageBecomesTheWordEveryDescriptionSpells(): void
    {
        // Given
        $exception = new InvalidClientMetadataException('scope', null, 'Not a scope token (RFC 6749 §3.3).');

        // When
        $response = RegistrationErrorResponse::fromException($exception);

        // Then
        static::assertSame('Not a scope token (RFC 6749 section 3.3).', $response->errorDescription);
    }

    #[Test]
    public function whatAClientWroteOutsideAsciiIsNotAnsweredBack(): void
    {
        // Given
        $exception = new InvalidClientMetadataException(null, null, 'The client has unknown keys: piège.');

        // When
        $response = RegistrationErrorResponse::fromException($exception);

        // Then
        static::assertSame('The client has unknown keys: pige.', $response->errorDescription);
    }
}
