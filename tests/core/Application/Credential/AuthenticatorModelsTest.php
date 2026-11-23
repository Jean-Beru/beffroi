<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Credential;

use Beffroi\Core\Application\Credential\AuthenticatorModels;
use Beffroi\Core\Bridge\Webauthn\AuthenticatorList;
use Beffroi\Core\Tests\Fixture\AuthenticatorLists;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\NilUuid;
use Symfony\Component\Uid\Uuid;

/**
 * WebAuthn Level 3 §6
 */
final class AuthenticatorModelsTest extends TestCase
{
    private const string AAGUID = 'ee882879-721c-4913-9775-3dfcce97072a';

    #[Test]
    public function theFirstSourceThatNamesTheModelAnswers(): void
    {
        // Given
        $models = new AuthenticatorModels([
            self::list([self::AAGUID => AuthenticatorLists::model('YubiKey 5 Series')]),
            self::list([self::AAGUID => AuthenticatorLists::model('Another name')]),
        ]);

        // When
        $model = $models->of(Fixtures::passkey(aaguid: Uuid::fromString(self::AAGUID)));

        // Then
        static::assertSame('YubiKey 5 Series', $model?->name);
    }

    #[Test]
    public function aSourceThatNamesNothingLeavesItToTheNextOne(): void
    {
        // Given
        $models = new AuthenticatorModels([
            self::list([Uuid::v4()->toRfc4122() => AuthenticatorLists::model('Another model')]),
            self::list([self::AAGUID => AuthenticatorLists::model('Proton Pass')]),
        ]);

        // When
        $model = $models->of(Fixtures::passkey(aaguid: Uuid::fromString(self::AAGUID)));

        // Then
        static::assertSame('Proton Pass', $model?->name);
    }

    #[Test]
    public function theAaguidAloneNamesTheModel(): void
    {
        // Given
        $models = new AuthenticatorModels([self::list([self::AAGUID => AuthenticatorLists::model('Proton Pass')])]);

        // When
        $model = $models->named(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame('Proton Pass', $model?->name);
    }

    #[Test]
    public function aModelNoSourceNamesIsUnknown(): void
    {
        // Given
        $models = new AuthenticatorModels([self::list([self::AAGUID => AuthenticatorLists::model('Proton Pass')])]);

        // When / Then
        static::assertNull($models->of(Fixtures::passkey(aaguid: Uuid::v4())));
    }

    /**
     * §18.1.1
     */
    #[Test]
    public function anAaguidOfZerosNamesNoModelWhateverASourceSays(): void
    {
        // Given
        $nil = new NilUuid();
        $models = new AuthenticatorModels([self::list([$nil->toRfc4122() => AuthenticatorLists::model('Anything')])]);

        // When / Then
        static::assertNull($models->of(Fixtures::passkey(aaguid: Uuid::fromString($nil->toRfc4122()))));
    }

    /**
     * @param non-empty-array<string, array<string, mixed>> $models
     */
    private static function list(array $models): AuthenticatorList
    {
        return AuthenticatorList::fromJson(AuthenticatorLists::document($models));
    }
}
