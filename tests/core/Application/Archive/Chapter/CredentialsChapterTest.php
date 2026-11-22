<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Archive\Chapter;

use Beffroi\Core\Application\Archive\Chapter\CredentialsChapter;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Totps;
use const JSON_THROW_ON_ERROR;
use function json_encode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CredentialsChapterTest extends TestCase
{
    #[Test]
    public function aCredentialIsOnItsKindItsNameAndItsDates(): void
    {
        // Given
        $user = Fixtures::user();
        $passkey = Fixtures::passkey($user);

        // When
        $lines = self::chapter([$passkey])->of($user);

        // Then
        static::assertSame(
            [
                [
                    'kind' => 'passkey',
                    'id' => $passkey->id->toRfc4122(),
                    'name' => 'YubiKey 5',
                    'external_id' => Base64Url::encode('credential-id'),
                    'created_at' => Fixtures::now()->format('c'),
                    'last_used_at' => null,
                    'revoked_at' => null,
                ],
            ],
            $lines,
        );
    }

    #[Test]
    public function noSecretOfACredentialReachesTheArchive(): void
    {
        // Given
        $user = Fixtures::user();
        $password = Fixtures::password($user);
        $totp = Totps::credential($user, new FakePasswordHasher());

        // When
        $written = json_encode(self::chapter([$password, $totp])->of($user), JSON_THROW_ON_ERROR);

        // Then
        static::assertStringNotContainsString($password->hash->encoded, $written);
        static::assertStringNotContainsString(Totps::SEED, $written);
        static::assertStringNotContainsString(Totps::BACKUP_CODES[0], $written);
    }

    #[Test]
    public function aKindThatCannotBeRevokedCarriesNoRevocation(): void
    {
        // Given
        $user = Fixtures::user();

        // When
        $lines = self::chapter([Fixtures::password($user)])->of($user);

        // Then
        static::assertNull($lines[0]['revoked_at']);
        static::assertNull($lines[0]['external_id']);
    }

    #[Test]
    public function aRevokedCredentialIsInTheArchiveWithTheDayItWasRevoked(): void
    {
        // Given
        $user = Fixtures::user();
        $passkey = Fixtures::passkey($user);
        $passkey->revoke(Fixtures::now());

        // When
        $lines = self::chapter([$passkey])->of($user);

        // Then
        static::assertSame(Fixtures::now()->format('c'), $lines[0]['revoked_at']);
    }

    /**
     * WebAuthn Level 3 §6.3.2
     */
    #[Test]
    public function theIdentifierAPartyPresentsIsWrittenInTheAlphabetItsColumnUses(): void
    {
        // Given
        $user = Fixtures::user();
        $credentialId = "\x4a\xfb\xff\x00\x80";

        // When
        $lines = self::chapter([Fixtures::passkey($user, credentialId: $credentialId)])->of($user);

        // Then
        static::assertSame(Base64Url::encode($credentialId), $lines[0]['external_id']);
    }

    #[Test]
    public function aCredentialWhoseIdentifierIsNotTextStillMakesADocument(): void
    {
        // Given
        $user = Fixtures::user();
        $chapter = self::chapter([Fixtures::passkey($user, credentialId: "\x4a\xfb\xff\x00\x80")]);

        // When / Then
        static::assertJson(json_encode($chapter->of($user), JSON_THROW_ON_ERROR));
    }

    #[Test]
    public function aPersonWithNoCredentialHasAnEmptyChapter(): void
    {
        // When / Then
        static::assertSame([], self::chapter()->of(Fixtures::user()));
    }

    /**
     * @param list<Credential> $credentials
     */
    private static function chapter(array $credentials = []): CredentialsChapter
    {
        $repository = new InMemoryCredentialRepository();
        foreach ($credentials as $credential) {
            $repository->save($credential);
        }

        return new CredentialsChapter($repository);
    }
}
