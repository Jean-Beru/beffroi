<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\SealedPerson;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Tests\Fixture\FakeSecretSealer;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The person a self-contained access token says it is about (issue #641, architecture §4.6): the claim the
 * issuer of that shape writes and the verifier of that shape opens.
 */
final class SealedPersonTest extends TestCase
{
    /**
     * The name the account carries, which is the one the journal of a person is read under (issue #588) and
     * the one a pairwise kind exists to keep from a client (OIDC Core §8.1).
     */
    private const string ACCOUNT = 'alice-as-this-provider-knows-her';

    private Tenant $tenant;

    private SealedPerson $persons;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->persons = Subjects::sealedPerson();
    }

    /**
     * Issue #641: what the issuer wrote is what the verifier reads, the person as their account names them,
     * which is what lets a token with no record behind it say who it is about.
     */
    #[Test]
    public function itReadsBackThePersonItSealed(): void
    {
        // Given
        $claim = $this->persons->claim($this->tenant, new Subject(self::ACCOUNT));

        // When
        $person = $this->persons->of($this->tenant, $claim);

        // Then
        static::assertSame(self::ACCOUNT, (string) $person);
    }

    /**
     * OIDC Core §8.1: the name the account carries is the one that links a person across sectors, so a
     * claim carrying it in the clear would hand it to every holder of the token. The claim is read by this
     * provider and by nobody else.
     */
    #[Test]
    public function itHandsTheNameOfTheAccountToNoHolderOfTheToken(): void
    {
        // When
        $claim = $this->persons->claim($this->tenant, new Subject(self::ACCOUNT));

        // Then
        static::assertStringNotContainsString(self::ACCOUNT, $claim);
        static::assertSame(new FakeSecretSealer()->seal($this->tenant, self::ACCOUNT), Base64Url::decode($claim));
    }

    /**
     * A token that carries no such claim is about whoever its "sub" names for the client it was written
     * for, which is what a token somebody signed in for and a token a client holds for itself are
     * (RFC 6749 §4.4).
     */
    #[Test]
    public function itNamesNobodyForATokenCarryingNoClaim(): void
    {
        // When
        $person = $this->persons->of($this->tenant, null);

        // Then
        static::assertNull($person);
    }

    /**
     * RFC 6750 §3.1, decision 0006: a claim this provider did not write there is refused rather than read
     * as saying nobody, and the refusal says no more than that the token is not one of ours.
     */
    #[Test]
    #[DataProvider('provideClaimsThisProviderDidNotWrite')]
    public function itRefusesAClaimThisProviderDidNotWrite(mixed $claim): void
    {
        // Then
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessageIs('invalid_token: The access token is not an access token issued by this provider.');

        // When
        $this->persons->of($this->tenant, $claim);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideClaimsThisProviderDidNotWrite(): iterable
    {
        yield 'a number' => [1];
        yield 'a list' => [[self::ACCOUNT]];
        yield 'an object' => [
            [
                'sub' => self::ACCOUNT,
            ],
        ];
        yield 'empty' => [''];
        yield 'not base64url' => ['sealed:acme:' . self::ACCOUNT];
        // RFC 4648 §5: the alphabet of base64url and no other, so a value written in the standard one is
        // not read as though this provider had written it
        yield 'the standard alphabet' => ['c2VhbGVkOmFjbWU6YWxpY+Ug'];
        yield 'the padding of base64' => ['c2VhbGVkOmFjbWU6YWxpY2U='];
        // an envelope of one tenant does not open for another, which is what the KMS guarantees
        // (architecture §3.3)
        yield 'sealed for another tenant' => [
            Base64Url::encode(new FakeSecretSealer()->seal(Fixtures::tenant('other', 'https://id.other.example'), self::ACCOUNT)),
        ];
        // OIDC Core §2: a subject is printable ASCII without spaces, and what an envelope of this provider
        // holds is a subject
        yield 'an envelope holding no subject' => [
            Base64Url::encode(new FakeSecretSealer()->seal(Fixtures::tenant(), 'a name with a space')),
        ];
        yield 'an empty envelope' => [Base64Url::encode(new FakeSecretSealer()->seal(Fixtures::tenant(), ''))];
    }
}
