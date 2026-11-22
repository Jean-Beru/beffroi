<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldSigning;
use Beffroi\Oidc\Application\Client\Registration\RegistrationSignedWithHeldKeys;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Registration §2, RFC 7591 §3.2.2
 */
final class RegistrationSignedWithHeldKeysTest extends TestCase
{
    #[Test]
    public function aClientSignedForWithAKeyTheTenantHoldsIsRegistered(): void
    {
        // Given
        $metadata = Registrations::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'id_token_signed_response_alg' => 'ES256',
        ]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // When
        self::keys([Algorithms::rs256(), Algorithms::es256()])->assertHolds(Fixtures::tenant(), $registration, $metadata);

        // Then
        static::assertSame('ES256', $registration->idToken->signature?->name());
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function provideDocumentsSignedWithoutAKey(): iterable
    {
        yield 'ID tokens' => [
            ['id_token_signed_response_alg' => 'ES256'],
            'id_token_signed_response_alg',
            'The client "drawn-identifier" would receive its ID tokens signed with ES256, which this tenant holds no active key for.',
        ];
        yield 'authorization responses' => [
            ['authorization_signed_response_alg' => 'PS256'],
            'authorization_signed_response_alg',
            'The client "drawn-identifier" would receive its authorization responses signed with PS256, which this tenant holds no active key for.',
        ];
        yield 'UserInfo responses' => [
            ['userinfo_signed_response_alg' => 'EdDSA'],
            'userinfo_signed_response_alg',
            'The client "drawn-identifier" would receive its UserInfo responses signed with EdDSA, which this tenant holds no active key for.',
        ];
    }

    /**
     * @param array<string, mixed> $signed
     */
    #[Test]
    #[DataProvider('provideDocumentsSignedWithoutAKey')]
    public function aDocumentTheTenantWouldSignWithoutAKeyIsRefused(array $signed, string $member, string $message): void
    {
        // Given
        $metadata = Registrations::registered(['redirect_uris' => ['https://rp.example/cb'], ...$signed]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // When
        try {
            self::keys([Algorithms::rs256()])->assertHolds(Fixtures::tenant(), $registration, $metadata);
            static::fail('The tenant holds no key to sign it with.');
        } catch (InvalidClientMetadataException $exception) {
            // Then
            static::assertSame($member, $exception->member);
            static::assertSame('the registration the client sent', $exception->source);
            static::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * OIDC Registration §2: an ID token is signed by default, with the algorithm the provider signs with.
     */
    #[Test]
    public function anAlgorithmLeftUnnamedIsTheDeploymentsAndNeverRefusesTheClient(): void
    {
        // Given
        $metadata = Registrations::registered(['redirect_uris' => ['https://rp.example/cb']]);
        $registration = Registrations::reader()->read('drawn-identifier', $metadata, true);

        // When
        self::keys([])->assertHolds(Fixtures::tenant(), $registration, $metadata);

        // Then
        static::assertSame('RS256', $registration->idToken->signature?->name());
    }

    /**
     * @param list<SignatureAlgorithmInterface> $held
     */
    private static function keys(array $held): RegistrationSignedWithHeldKeys
    {
        return new RegistrationSignedWithHeldKeys(HeldSigning::of($held));
    }
}
