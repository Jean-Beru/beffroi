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
 * RFC 6749 §5.2
 */
final class ClientAuthenticationFailureTest extends TestCase
{
    /**
     * RFC 6749 §5.2
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
