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
 * Architecture §4.6
 */
final class SealedPersonTest extends TestCase
{
    private const string ACCOUNT = 'alice-as-this-provider-knows-her';

    private Tenant $tenant;

    private SealedPerson $persons;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->persons = Subjects::sealedPerson();
    }

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
     * OIDC Core §8.1
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
     * RFC 6749 §4.4
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
     * RFC 6750 §3.1, Decision 0006
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
        // RFC 4648 §5: a value in the standard alphabet was not written by this provider.
        yield 'the standard alphabet' => ['c2VhbGVkOmFjbWU6YWxpY+Ug'];
        yield 'the padding of base64' => ['c2VhbGVkOmFjbWU6YWxpY2U='];
        yield 'sealed for another tenant' => [
            Base64Url::encode(new FakeSecretSealer()->seal(Fixtures::tenant('other', 'https://id.other.example'), self::ACCOUNT)),
        ];
        // OIDC Core §2: a subject is printable ASCII without spaces.
        yield 'an envelope holding no subject' => [
            Base64Url::encode(new FakeSecretSealer()->seal(Fixtures::tenant(), 'a name with a space')),
        ];
        yield 'an empty envelope' => [Base64Url::encode(new FakeSecretSealer()->seal(Fixtures::tenant(), ''))];
    }
}
