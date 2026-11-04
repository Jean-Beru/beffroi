<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery;

use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\FakeSignatureAlgorithm;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Tests\Fixture\FakeClientAuthenticationMethod;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AnnouncedAlgorithmsTest extends TestCase
{
    #[Test]
    public function theSigningAlgorithmsAreThoseWiredInTheirOrder(): void
    {
        // When
        $signing = self::announced()->signing();

        // Then
        static::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA'], $signing);
    }

    #[Test]
    public function anAlgorithmTheModuleKnowsNothingAboutIsAnnouncedBecauseItIsWired(): void
    {
        // Given
        $announced = self::announced(new JoseSignatureAlgorithms([new FakeSignatureAlgorithm()]));

        // When
        $signing = $announced->signing();

        // Then
        static::assertSame(['ES256UNWIRED'], $signing);
    }

    /**
     * RFC 9701 §6
     */
    #[Test]
    public function theDefaultSigningIsTheOneAlgorithmWiredFirst(): void
    {
        // Given
        $announced = self::announced(new JoseSignatureAlgorithms([Algorithms::es256(), Algorithms::rs256()]));

        // When
        $signing = $announced->defaultSigning();

        // Then
        static::assertSame(['ES256'], $signing);
    }

    /**
     * OIDC Discovery §3
     */
    #[Test]
    public function theEncryptionOfADocumentIsThePairOfMembersNamedAfterIt(): void
    {
        // When
        $members = self::announced()->encryptionOf('id_token_encryption');

        // Then
        static::assertSame(
            [
                'id_token_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
                'id_token_encryption_enc_values_supported' => ['A256GCM'],
            ],
            $members,
        );
    }

    #[Test]
    #[DataProvider('provideIncompleteEncryptionWirings')]
    public function aProviderNobodyEncryptsToAnnouncesNeitherMember(
        KeyEncryptionAlgorithmsInterface $keyEncryption,
        ContentEncryptionAlgorithmsInterface $contentEncryption,
    ): void {
        // Given
        $announced = self::announced(keyEncryption: $keyEncryption, contentEncryption: $contentEncryption);

        // When
        $members = $announced->encryptionOf('request_object_encryption');

        // Then
        static::assertSame([], $members);
    }

    /**
     * @return iterable<string, array{KeyEncryptionAlgorithmsInterface, ContentEncryptionAlgorithmsInterface}>
     */
    public static function provideIncompleteEncryptionWirings(): iterable
    {
        yield 'nothing wired' => [Algorithms::noKeyEncryption(), Algorithms::noContentEncryption()];
        yield 'an alg that would open nothing' => [Algorithms::keyEncryption(), Algorithms::noContentEncryption()];
        yield 'an enc nothing unwraps a key for' => [Algorithms::noKeyEncryption(), Algorithms::contentEncryption()];
    }

    /**
     * OIDC Core §9
     */
    #[Test]
    public function whatAnAssertionMayBeSignedWithIsWhatTheMethodsSayEachOnce(): void
    {
        // Given
        $methods = [Methods::clientSecretBasic(), Methods::privateKeyJwt(), Methods::clientSecretJwt()];

        // When
        $algorithms = self::announced()->assertionSigning($methods);

        // Then
        static::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'], $algorithms);
    }

    #[Test]
    public function aMethodTheModuleKnowsNothingAboutNamesWhatSignsItsAssertion(): void
    {
        // When
        $algorithms = self::announced()->assertionSigning([new FakeClientAuthenticationMethod()]);

        // Then
        static::assertSame(['SM256'], $algorithms);
    }

    #[Test]
    public function aDeploymentThatReadsNoAssertionAnnouncesNoAlgorithmForOne(): void
    {
        // When
        $algorithms = self::announced()->assertionSigning([Methods::clientSecretBasic(), Methods::none()]);

        // Then
        static::assertSame([], $algorithms);
    }

    private static function announced(
        ?SignatureAlgorithmsInterface $signature = null,
        ?KeyEncryptionAlgorithmsInterface $keyEncryption = null,
        ?ContentEncryptionAlgorithmsInterface $contentEncryption = null,
    ): AnnouncedAlgorithms {
        return new AnnouncedAlgorithms(
            $signature ?? Algorithms::all(),
            $keyEncryption ?? Algorithms::keyEncryption(),
            $contentEncryption ?? Algorithms::contentEncryption(),
        );
    }
}
