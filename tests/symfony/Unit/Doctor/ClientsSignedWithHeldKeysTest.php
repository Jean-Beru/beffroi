<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctor;

use App\Doctor\ClientsSignedWithHeldKeys;
use App\Tests\Symfony\Fixture\AmbientTenant;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldSigning;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Tests\Fixture\Registrations;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClientsSignedWithHeldKeysTest extends TestCase
{
    #[Test]
    public function aClientSignedForWithAKeyTheTenantHoldsIsGreen(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $check = self::check($tenant, [Algorithms::rs256(), Algorithms::es256()], ['id_token_signed_response_alg' => 'ES256']);

        // When
        $finding = $check->finding();

        // Then
        static::assertSame(
            [true, ['The tenant "acme" holds an active key for every algorithm it signs the documents of its clients with.']],
            [$finding->green, $finding->lines],
        );
    }

    #[Test]
    public function aClientSignedForWithoutAKeyIsRedAndSaysWhatFails(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $check = self::check($tenant, [Algorithms::rs256()], ['id_token_signed_response_alg' => 'ES256']);

        // When
        $finding = $check->finding();

        // Then
        static::assertSame(
            [
                false,
                'The client "rp" receives its ID tokens signed with ES256, which the tenant "acme" holds no active key for: the first one it asks for fails with a server error.',
            ],
            [$finding->green, $finding->lines[0] ?? null],
        );
    }

    /**
     * OIDC Registration §2: an ID token is signed by default, with the algorithm the provider signs with.
     */
    #[Test]
    public function theDefaultAlgorithmOfAClientThatNamesNoneNeedsItsKey(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $check = self::check($tenant, [Algorithms::es256()], []);

        // When
        $finding = $check->finding();

        // Then
        static::assertSame(
            [
                'The client "rp" receives its ID tokens signed with RS256, which the tenant "acme" holds no active key for: the first one it asks for fails with a server error.',
                'The client "rp" receives its authorization responses signed with RS256, which the tenant "acme" holds no active key for: the first one it asks for fails with a server error.',
                ClientsSignedWithHeldKeys::WHAT_TO_DO,
            ],
            $finding->lines,
        );
    }

    #[Test]
    public function aRedFindingSaysWhatMakesItGreen(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $check = self::check($tenant, [Algorithms::rs256()], ['userinfo_signed_response_alg' => 'EdDSA']);

        // When
        $finding = $check->finding();

        // Then
        static::assertSame(ClientsSignedWithHeldKeys::WHAT_TO_DO, $finding->lines[1] ?? null);
    }

    #[Test]
    public function aTenantThatCannotBeReadIsRed(): void
    {
        // Given
        $check = new ClientsSignedWithHeldKeys(new AmbientTenant(null), [new InMemoryClientRepository()], HeldSigning::everyAlgorithm(), Algorithms::all());

        // When
        $finding = $check->finding();

        // Then
        static::assertSame(
            [false, ['The clients of the tenant and its keys cannot be read: No tenant is ambient.']],
            [$finding->green, $finding->lines],
        );
    }

    /**
     * @param list<SignatureAlgorithmInterface> $held
     * @param array<string, mixed> $signed
     */
    private static function check(Tenant $tenant, array $held, array $signed): ClientsSignedWithHeldKeys
    {
        $metadata = Registrations::registered([
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
            ...$signed,
        ]);
        $clients = new InMemoryClientRepository();
        $clients->save(new Client($tenant, Registrations::reader()->read('rp', $metadata)));

        return new ClientsSignedWithHeldKeys(new AmbientTenant($tenant), [$clients], HeldSigning::of($held), Algorithms::all());
    }
}
