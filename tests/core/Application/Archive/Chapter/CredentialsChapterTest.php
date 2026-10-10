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

/**
 * Issue #453: the archive holds the credentials of a person without their secrets. The chapter names the
 * fields it writes and asks a credential for nothing else, so a kind that gains a field gains nothing
 * here: a hash of a password, a TOTP secret and a backup code are what a serializer would have put in a
 * file a person downloads and sends on.
 */
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

    /**
     * The criterion of the issue, held against the document and not against a field: whatever a kind
     * carries, what reaches the file is what this chapter named.
     */
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

    /**
     * A password is replaced and not revoked, so it carries no date of a revocation: what a kind can do,
     * it says by an interface and not by a field left empty everywhere else.
     */
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
     * A credential ID is what the authenticator issued (WebAuthn Level 3 §6.3.2), octets and not text, so
     * it reaches the document in the alphabet the column holding it uses. A document is JSON: octets that
     * are not text are what leaves a person with no document at all.
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
