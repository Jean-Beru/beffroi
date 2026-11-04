<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTls;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §3.3
 */
final class AnnouncedMutualTlsTest extends TestCase
{
    #[Test]
    #[DataProvider('provideWirings')]
    public function itBindsTokensToCertificatesWhereSuchAMethodIsWired(ClientAuthenticationMethods $methods, bool $bound): void
    {
        // Given
        $announced = new AnnouncedMutualTls($methods);

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'tls_client_certificate_bound_access_tokens' => $bound,
            ],
            $members,
        );
    }

    /**
     * @return iterable<string, array{ClientAuthenticationMethods, bool}>
     */
    public static function provideWirings(): iterable
    {
        yield 'a deployment wired with mutual TLS' => [Methods::all(), true];
        yield 'a deployment wired without it' => [new ClientAuthenticationMethods([Methods::clientSecretBasic()]), false];
    }
}
