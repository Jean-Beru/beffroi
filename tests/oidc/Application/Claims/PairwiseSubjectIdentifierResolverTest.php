<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use function base64_encode;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPairwiseSubjectRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Methods;
use Beffroi\Oidc\Tests\Fixture\FixedPairwiseSalt;
use Beffroi\Oidc\Tests\Fixture\PairwiseSaltBehindAnOutage;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use function hash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function strtr;

/**
 * OIDC Core §8.1
 */
final class PairwiseSubjectIdentifierResolverTest extends TestCase
{
    private const string SALT = 'a-salt-the-deployment-drew-once!';

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function theIdentifierIsTheOneTheSpecificationComputes(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $client = Clients::pairwise($tenant, redirectUri: 'https://rp.example/callback');

        // When
        $subject = self::resolver()->resolve($user, $client);

        // Then
        $digest = hash('sha256', 'rp.example' . $user->subject->value . self::SALT, true);
        static::assertSame(rtrim(strtr(base64_encode($digest), '+/', '-_'), '='), $subject->value);
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function aKmsThatDoesNotAnswerIsToldWhenTheClientIsOpened(): void
    {
        // Given
        $salts = new PairwiseSaltBehindAnOutage(new FixedPairwiseSalt(self::SALT));
        $salts->down = true;

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs(PairwiseSaltBehindAnOutage::WORDS_OF_THE_KMS);

        // When
        Subjects::pairwiseKind($salts)->open(Clients::pairwise(Fixtures::tenant()));
    }

    #[Test]
    public function anIdentifierIsAssignedFromWhatWasOpenedWhateverTheKmsAnswersAfterwards(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $salts = new PairwiseSaltBehindAnOutage(new FixedPairwiseSalt(self::SALT));
        $opened = Subjects::pairwiseKind($salts)->open(Clients::pairwise($tenant, redirectUri: 'https://rp.example/callback'));
        $salts->down = true;

        // When
        $subject = $opened->subjectOf($user);

        // Then
        $digest = hash('sha256', 'rp.example' . $user->subject->value . self::SALT, true);
        static::assertSame(rtrim(strtr(base64_encode($digest), '+/', '-_'), '='), $subject->value);
    }

    #[Test]
    public function aUserOfAnotherTenantIsGivenNoIdentifierUnderTheSaltOfTheClient(): void
    {
        // Given
        $here = Fixtures::tenant('here', 'https://here.example');
        $there = Fixtures::tenant('there', 'https://there.example');
        $opened = self::resolver()->open(Clients::pairwise($here));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('A user of the tenant "there" has no identifier computed with the salt of the tenant "here".');

        // When
        $opened->subjectOf(Fixtures::user($there));
    }

    #[Test]
    public function twoSectorsSeeOneUserUnderTwoIdentifiers(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $resolver = self::resolver();

        // When
        $here = $resolver->resolve($user, Clients::pairwise($tenant, 'one', 'https://one.example/callback'));
        $there = $resolver->resolve($user, Clients::pairwise($tenant, 'other', 'https://other.example/callback'));

        // Then
        static::assertNotSame($here->value, $there->value);
    }

    /**
     * CIBA Core §4
     */
    #[Test]
    public function twoBackchannelClientsOfOneHostSeeOneUserUnderOneIdentifier(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $resolver = self::resolver();

        // When
        $here = $resolver->resolve($user, self::backchannel($tenant, 'one', 'https://terminal.example/jwks.json'));
        $there = $resolver->resolve($user, self::backchannel($tenant, 'other', 'https://terminal.example/keys.json'));

        // Then
        $digest = hash('sha256', 'terminal.example' . $user->subject->value . self::SALT, true);
        static::assertSame(rtrim(strtr(base64_encode($digest), '+/', '-_'), '='), $here->value);
        static::assertSame($here->value, $there->value);
    }

    #[Test]
    public function twoBackchannelClientsOfTwoHostsSeeOneUserUnderTwoIdentifiers(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $resolver = self::resolver();

        // When
        $here = $resolver->resolve($user, self::backchannel($tenant, 'one', 'https://terminal.example/jwks.json'));
        $there = $resolver->resolve($user, self::backchannel($tenant, 'other', 'https://other.example/jwks.json'));

        // Then
        static::assertNotSame($here->value, $there->value);
    }

    #[Test]
    public function theIdentifierOfABackchannelClientNamesItsUserInThatSector(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $resolver = self::resolver();
        $client = self::backchannel($tenant, 'one', 'https://terminal.example/jwks.json');
        $subject = $resolver->resolve($user, $client);

        // When
        $found = $resolver->findUser($client, $subject);
        $elsewhere = $resolver->findUser(self::backchannel($tenant, 'other', 'https://other.example/jwks.json'), $subject);

        // Then
        static::assertSame($user, $found);
        static::assertNull($elsewhere);
    }

    private static function backchannel(Tenant $tenant, string $clientId, string $jwksUri): Client
    {
        return Clients::backchannel(
            $tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            $clientId,
            jwksUri: $jwksUri,
            subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE,
            method: Methods::privateKeyJwt(),
        );
    }

    /**
     * OIDC Registration §5
     */
    #[Test]
    public function twoClientsOfOneSectorSeeOneUserUnderOneIdentifier(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $resolver = self::resolver();
        $document = 'https://sector.example/redirect_uris.json';

        // When
        $here = $resolver->resolve($user, Clients::pairwise($tenant, 'one', 'https://one.example/callback', $document));
        $there = $resolver->resolve($user, Clients::pairwise($tenant, 'other', 'https://other.example/callback', $document));

        // Then
        static::assertSame($here->value, $there->value);
    }

    #[Test]
    public function theSameUserAndSectorGiveTheSameIdentifierEveryTime(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $client = Clients::pairwise($tenant);

        // When
        $first = self::resolver()->resolve($user, $client);
        $again = self::resolver()->resolve($user, $client);

        // Then
        static::assertSame($first->value, $again->value);
    }

    #[Test]
    public function twoTenantsGiveTheSameUserAndSectorTwoIdentifiers(): void
    {
        // Given
        $here = Fixtures::tenant('here', 'https://here.example');
        $there = Fixtures::tenant('there', 'https://there.example');
        $user = Fixtures::user($here);
        $resolver = Subjects::pairwiseKind(new FixedPairwiseSalt(perTenant: true));

        // When
        $ofHere = $resolver->resolve($user, Clients::pairwise($here));
        $ofThere = $resolver->resolve(Fixtures::user($there, subject: $user->subject->value), Clients::pairwise($there));

        // Then
        static::assertNotSame($ofHere->value, $ofThere->value);
    }

    #[Test]
    public function anIdentifierItAssignedNamesItsUserAgain(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $client = Clients::pairwise($tenant);
        $resolver = self::resolver();
        $subject = $resolver->resolve($user, $client);

        // When
        $found = $resolver->findUser($client, $subject);

        // Then
        static::assertSame($user, $found);
    }

    #[Test]
    public function anIdentifierOfOneSectorNamesNobodyToAnother(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $user = Fixtures::user($tenant);
        $resolver = self::resolver();
        $subject = $resolver->resolve($user, Clients::pairwise($tenant, 'one', 'https://one.example/callback'));

        // When
        $found = $resolver->findUser(Clients::pairwise($tenant, 'other', 'https://other.example/callback'), $subject);

        // Then
        static::assertNull($found);
    }

    #[Test]
    public function aValueItNeverAssignedNamesNobody(): void
    {
        // When
        $found = self::resolver()->findUser(Clients::pairwise(Fixtures::tenant()), new Subject('a-value-nobody-was-handed'));

        // Then
        static::assertNull($found);
    }

    #[Test]
    public function itNamesTheKindOfTheSpecification(): void
    {
        // When / Then
        static::assertSame('pairwise', self::resolver()->subjectType());
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function itRefusesARegistrationThatNamesNoSector(): void
    {
        // Given
        $service = Clients::service(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        $this->expectException(InvalidClientMetadataException::class);
        $this->expectExceptionMessageIsOrContains('registers nothing that says which sector its subject identifiers belong to');

        // When
        self::resolver()->assertAssignable($service->registration);
    }

    #[Test]
    public function itAsksNothingOfARegistrationThatNamesOne(): void
    {
        // Given
        $client = Clients::pairwise(Fixtures::tenant());

        // When
        self::resolver()->assertAssignable($client->registration);

        // Then
        static::assertNotNull($client->registration->subjectType);
    }

    private static function resolver(): PairwiseSubjectIdentifierResolver
    {
        return Subjects::pairwiseKind(new FixedPairwiseSalt(self::SALT), new InMemoryPairwiseSubjectRepository());
    }
}
