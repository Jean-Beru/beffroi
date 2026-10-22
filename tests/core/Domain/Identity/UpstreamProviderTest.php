<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #781, decision 0029: an upstream provider as the deployment declares it, which answers for its
 * e-mail domains and creates the persons of those domains only.
 */
final class UpstreamProviderTest extends TestCase
{
    private const string PROVIDER = 'https://idp.acme.example/saml';

    #[Test]
    public function itHoldsItsDomainsInLowercaseAndEachOnce(): void
    {
        // When
        $provider = new UpstreamProvider(self::PROVIDER, ['Acme.Example', 'acme.test', 'ACME.EXAMPLE']);

        // Then
        static::assertSame(['acme.example', 'acme.test'], $provider->domains);
    }

    #[Test]
    public function itFillsEachClaimOnceInTheOrderItWasDeclared(): void
    {
        // When
        $provider = new UpstreamProvider(self::PROVIDER, ['acme.example'], ['family_name', 'given_name', 'family_name']);

        // Then
        static::assertSame(['family_name', 'given_name'], $provider->claims);
    }

    /**
     * @param list<string> $domains
     * @param list<string> $claims
     */
    #[Test]
    #[DataProvider('provideWhatIsNotAProvider')]
    public function whatIsNotAProviderIsRefused(string $name, array $domains, array $claims, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new UpstreamProvider($name, $domains, $claims);
    }

    /**
     * @return iterable<string, array{string, list<string>, list<string>, string}>
     */
    public static function provideWhatIsNotAProvider(): iterable
    {
        yield 'unnamed' => ['', ['acme.example'], [], 'An upstream provider is named.'];
        yield 'an empty domain' => [
            self::PROVIDER,
            ['acme.example', ''],
            [],
            'A domain the upstream provider "https://idp.acme.example/saml" answers for is named.',
        ];
        // the address is not a claim of the profile: every provider holds it, its domains being read from it
        yield 'the address among the claims of the profile' => [
            self::PROVIDER,
            ['acme.example'],
            ['email'],
            'The upstream provider "https://idp.acme.example/saml" fills "email", which is no claim of the profile.',
        ];
        yield 'a claim no profile holds' => [
            self::PROVIDER,
            ['acme.example'],
            ['groups'],
            'The upstream provider "https://idp.acme.example/saml" fills "groups", which is no claim of the profile.',
        ];
    }

    /**
     * RFC 4343 §3: a domain is compared without regard to ASCII case, and exactly otherwise.
     */
    #[Test]
    #[DataProvider('provideAddresses')]
    public function itAnswersForTheAddressesOfItsDomainsOnly(string $address, bool $answers): void
    {
        // Given
        $provider = new UpstreamProvider(self::PROVIDER, ['acme.example', 'eu.acme.test']);

        // When / Then
        static::assertSame($answers, $provider->answersFor(new EmailAddress($address)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideAddresses(): iterable
    {
        yield 'of its first domain' => ['alice@acme.example', true];
        yield 'of another of its domains' => ['alice@eu.acme.test', true];
        yield 'of its domain in another case' => ['alice@ACME.Example', true];
        yield 'of a subdomain of its domain' => ['alice@eu.acme.example', false];
        yield 'of the parent of its domain' => ['alice@acme.test', false];
        yield 'of a domain it does not declare' => ['alice@initech.example', false];
    }

    /**
     * Decision 0002: a person it creates names it as its source, which holds the address and the claims it
     * fills, so that a manual description leaves them to it.
     */
    #[Test]
    public function thePersonItCreatesNamesItAndHoldsTheAddressAndTheClaimsItFills(): void
    {
        // Given
        $provider = new UpstreamProvider(self::PROVIDER, ['acme.example'], ['given_name', 'family_name']);

        // When / Then
        static::assertEquals(UserSource::upstream(self::PROVIDER, ['email', 'given_name', 'family_name']), $provider->source());
    }

    #[Test]
    #[DataProvider('provideSources')]
    public function itIsTheSourceOfThePersonsItCreatedOnly(UserSource $source, bool $isTheSource): void
    {
        // Given
        $provider = new UpstreamProvider(self::PROVIDER, ['acme.example']);
        $user = User::create(Uuid::v7(), Fixtures::tenant(), new Subject('alice-subject'), 'alice', Fixtures::now(), source: $source);

        // When / Then
        static::assertSame($isTheSource, $provider->isTheSourceOf($user));
    }

    /**
     * @return iterable<string, array{UserSource, bool}>
     */
    public static function provideSources(): iterable
    {
        yield 'a person it created' => [UserSource::upstream(self::PROVIDER, ['email']), true];
        yield 'a person another provider created' => [UserSource::upstream('https://idp.initech.example/saml', ['email']), false];
        yield 'a local person' => [UserSource::local(), false];
    }
}
