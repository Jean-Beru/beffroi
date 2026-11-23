<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use function array_map;
use Beffroi\Core\Application\Credential\DeclaredModels;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * WebAuthn Level 3 §6.5.1
 */
final class DeclaredModelsTest extends TestCase
{
    private const string YUBIKEY = 'cb69481e-8ff7-4039-93ec-0a2729a154a8';

    private const string PROTON_PASS = '50726f74-6f6e-5061-7373-50726f746f6e';

    #[Test]
    public function everyModelThePasskeysOfThePersonDeclareIsNamedOnceInTheOrderOfEnrolment(): void
    {
        // Given
        $alice = Fixtures::user();
        $credentials = new InMemoryCredentialRepository();
        $credentials->save(Fixtures::passkey($alice, credentialId: 'first', createdAt: Fixtures::now(), aaguid: Uuid::fromString(self::PROTON_PASS)));
        $credentials->save(Fixtures::passkey(
            $alice,
            credentialId: 'second',
            createdAt: Fixtures::now()->modify('+1 day'),
            aaguid: Uuid::fromString(self::YUBIKEY),
        ));
        $credentials->save(Fixtures::passkey(
            $alice,
            credentialId: 'third',
            createdAt: Fixtures::now()->modify('+2 days'),
            aaguid: Uuid::fromString(self::PROTON_PASS),
        ));
        $credentials->save(Fixtures::password($alice));
        $credentials->save(Fixtures::passkey(Fixtures::user(username: 'bob', subject: 'bob-subject'), credentialId: 'bob', aaguid: Uuid::v4()));

        // When
        $models = new DeclaredModels($credentials)->of($alice, PasskeyCredential::class);

        // Then
        static::assertSame([self::PROTON_PASS, self::YUBIKEY], array_map(static fn (Uuid $model): string => $model->toRfc4122(), $models));
    }
}
