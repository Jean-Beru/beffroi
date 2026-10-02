<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedRequestObjects;
use Beffroi\Oidc\Port\UnsignedRequestObjectsInterface;
use Beffroi\Oidc\Tests\Fixture\RequestObjectSignings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §6: the provider reads a request object passed by value or by reference, and a "request_uri"
 * is registered beforehand (decision 0006, no outbound fetch of an unregistered URI).
 */
final class AnnouncedRequestObjectsTest extends TestCase
{
    #[Test]
    public function itAnnouncesBothWaysOfPassingOneAndTheRegistrationItAsksFor(): void
    {
        // Given
        $announced = self::announced(RequestObjectSignings::everyClientSignsThem());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertTrue($members['request_parameter_supported']);
        static::assertTrue($members['request_uri_parameter_supported']);
        static::assertTrue($members['require_request_uri_registration']);
    }

    /**
     * OIDC Discovery §3 and issue #164: what a client may encrypt a request object to the provider with
     * is what the wiring gave it.
     */
    #[Test]
    public function itAnnouncesWhatARequestObjectMayBeEncryptedToItWith(): void
    {
        // Given
        $announced = self::announced(RequestObjectSignings::everyClientSignsThem());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['ECDH-ES+A256KW', 'RSA-OAEP-256'], $members['request_object_encryption_alg_values_supported']);
        static::assertSame(['A256GCM'], $members['request_object_encryption_enc_values_supported']);
    }

    /**
     * OIDC Registration §2 and decision 0006: "none" is announced beside the algorithms when a client of
     * the tenant registered it, and a deployment whose clients all sign their request objects does not
     * announce that it would read an unsigned one (issue #98).
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideWhatTheClientsRegistered')]
    public function theSigningAlgorithmsAreTheWiredOnesAndWhatAClientRegistered(
        UnsignedRequestObjectsInterface $unsigned,
        array $expected,
    ): void {
        // Given
        $announced = self::announced($unsigned);

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame($expected, $members['request_object_signing_alg_values_supported']);
    }

    /**
     * @return iterable<string, array{UnsignedRequestObjectsInterface, list<string>}>
     */
    public static function provideWhatTheClientsRegistered(): iterable
    {
        yield 'every client signs its objects' => [RequestObjectSignings::everyClientSignsThem(), ['RS256', 'PS256', 'ES256', 'EdDSA']];
        yield 'one client registered none' => [RequestObjectSignings::oneClientSendsThemUnsigned(), ['RS256', 'PS256', 'ES256', 'EdDSA', 'none']];
    }

    private static function announced(UnsignedRequestObjectsInterface $unsigned): AnnouncedRequestObjects
    {
        return new AnnouncedRequestObjects(
            $unsigned,
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        );
    }
}
