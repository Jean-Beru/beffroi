<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Claims;

use function base64_encode;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Heidi\Oidc\Bridge\InMemory\InMemoryPairwiseSubjectRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FixedPairwiseSalt;
use Heidi\Oidc\Tests\Fixture\Subjects;
use function hash;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function strtr;

/**
 * OIDC Core §8.1: what each sector sees of a user, and what nobody can compare across two of them.
 */
final class PairwiseSubjectIdentifierResolverTest extends TestCase
{
    private const string SALT = 'a-salt-the-deployment-drew-once!';

    /**
     * OIDC Core §8.1: the SHA-256 of the sector, the local account identifier and the salt, in base64url.
     * The value is written out, because a change to what is hashed is every identifier of every client
     * changed, and this test is what says so.
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
     * The property pairwise identifiers exist for: two clients of two sectors cannot find out they are
     * looking at the same person by comparing the strings they hold.
     */
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
     * CIBA Core §4: a client of the backchannel flow registers no redirection URI, so the sector its "sub"
     * is computed per is the host of its "jwks_uri". Two such clients publishing their keys on one host are
     * one sector and see one user under one identifier, exactly as two clients of one redirection host are.
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

    /**
     * And the way back holds for them too: the identifier a backchannel client was handed names its user
     * to that client's sector, and to no other.
     */
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
        );
    }

    /**
     * OIDC Registration §5: what a sector is for. Two clients that register the same document belong to one
     * sector, whatever their own hosts are, and one user is one account to both of them.
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

    /**
     * The identifier is computed and not drawn, so it is the same one at every document written afterwards
     * and in every worker at once.
     */
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

    /**
     * The salt is a secret of the deployment and of its tenant: two tenants that share a user and a sector
     * do not share an identifier for them, so nothing carries across a deployment either.
     */
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

    /**
     * The way back: an identifier this resolver wrote down names its user again, to a client of the sector
     * it was written for.
     */
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

    /**
     * The property again, from the other side: the string one sector holds names nobody to a client of
     * another, which is what makes a "sub" useless to whoever it was not written for.
     */
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

    /**
     * A value nobody was ever handed names nobody, as a subject that belongs to nobody does.
     */
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
     * OIDC Core §8.1: a client of this kind has a sector, and a registration that names none is refused
     * where a registration meets the wiring, not at the first token it asks for.
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
