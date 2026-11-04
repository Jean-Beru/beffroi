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
 * OIDC Core §6, Decision 0006
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
     * OIDC Discovery §3
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
     * OIDC Registration §2, Decision 0006
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
