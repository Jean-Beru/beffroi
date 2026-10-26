<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What a client authentication method refuses with becomes the protocol error the client reads, so its description
 * is held to the rule of one (RFC 6749 §5.2) where it is written.
 */
final class ClientAuthenticationFailureTest extends TestCase
{
    /**
     * RFC 6749 §5.2 (issue #863): a description no protocol error could carry is refused where it is written, and not
     * by the endpoint that would have answered with it.
     */
    #[Test]
    #[DataProvider('provideDescriptionsNoErrorCarries')]
    public function aDescriptionNoProtocolErrorCouldCarryIsAProgrammingError(string $description): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('RFC 6749');

        // When
        ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, null, null, $description);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDescriptionsNoErrorCarries(): iterable
    {
        yield 'double quotes' => ['The client_assertion_type parameter must be "jwt-bearer".'];
        yield 'beyond ASCII' => ['Un accent aigu : é.'];
    }
}
