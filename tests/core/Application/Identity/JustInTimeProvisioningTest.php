<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Identity;

use Beffroi\Core\Application\Credential\ActiveCredentials;
use Beffroi\Core\Application\Credential\ActivePassword;
use Beffroi\Core\Application\Credential\BreachedPasswordRefusal;
use Beffroi\Core\Application\Credential\EnrolmentRefusal;
use Beffroi\Core\Application\Identity\IdentityLinker;
use Beffroi\Core\Application\Identity\JustInTimeProvisioning;
use Beffroi\Core\Application\Identity\UpstreamProvisioningRefusedException;
use Beffroi\Core\Application\Identity\UserProvisioner;
use Beffroi\Core\Bridge\InMemory\InMemoryCredentialRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryLinkedIdentityRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Bridge\Password\NativePasswordHasher;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Event\PersonProvisioned;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Identity\UserSource;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use Beffroi\Core\Tests\Fixture\WritesAsTheyCome;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #781, decision 0002: the person an upstream provider names at a sign-in through it, created at the
 * first one with its provenance and its linked identity, and found again at the next ones by that identity.
 * What the provider writes of a person keeps to its domains and to an address nobody else holds (decision
 * 0029), and no existing account is linked on its own (spike 12, beffroi-auth/beffroi#85).
 */
final class JustInTimeProvisioningTest extends TestCase
{
    private const string PROVIDER = 'https://idp.acme.example/saml';

    private const string SUBJECT = 'a7f3c2e1-alice';

    private const string ADDRESS = 'alice@acme.example';

    private Tenant $tenant;

    private UpstreamProvider $provider;

    private InMemoryUserRepository $users;

    private InMemoryLinkedIdentityRepository $identities;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private WritesAsTheyCome $writes;

    private UserProvisioner $provisioner;

    private IdentityLinker $linker;

    private JustInTimeProvisioning $provisioning;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->provider = new UpstreamProvider(self::PROVIDER, ['acme.example'], ['given_name', 'family_name', 'birthdate']);
        $this->users = new InMemoryUserRepository();
        $this->identities = new InMemoryLinkedIdentityRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-10-22T09:00:00+00:00');
        $this->writes = new WritesAsTheyCome();
        $credentials = new InMemoryCredentialRepository();
        $this->provisioner = new UserProvisioner(
            $this->users,
            $credentials,
            new ActivePassword(new ActiveCredentials($credentials)),
            new NativePasswordHasher(),
            new BreachedPasswordRefusal(BreachedPasswordsOfARecord::holding([])),
            new EnrolmentRefusal(),
            new SymfonyUuidGenerator(),
            $this->clock,
        );
        $this->linker = new IdentityLinker($this->identities, new SymfonyUuidGenerator(), $this->clock);
        $this->provisioning = new JustInTimeProvisioning(
            $this->identities,
            $this->users,
            $this->provisioner,
            $this->linker,
            $this->events,
            $this->clock,
            $this->writes,
        );
    }

    /**
     * The acceptance of the issue, its first half: one person, named by its address, whose source is the
     * provider and holds what that provider fills, its address verified, the provider answering for its
     * domain.
     */
    #[Test]
    public function aFirstSignInCreatesThePersonTheProviderNames(): void
    {
        // When
        $alice = $this->signIn();

        // Then
        static::assertSame($alice, $this->users->find($alice->id));
        static::assertSame($this->tenant, $alice->tenant);
        static::assertSame(self::ADDRESS, $alice->username);
        static::assertSame(self::ADDRESS, $alice->email?->value);
        static::assertTrue($alice->emailVerified);
        static::assertEquals(new Profile(givenName: 'Alice', familyName: 'Liddell'), $alice->profile);
        static::assertEquals(UserSource::upstream(self::PROVIDER, ['email', 'given_name', 'family_name', 'birthdate']), $alice->source);
        static::assertEquals($this->clock->now(), $alice->createdAt);
    }

    /**
     * The acceptance of the issue, its second half: one linked identity, which names the person created and
     * holds the snapshot of what the provider said.
     */
    #[Test]
    public function aFirstSignInLinksThePersonToTheSubjectTheProviderGave(): void
    {
        // When
        $alice = $this->signIn();

        // Then
        $identities = $this->identities->of($alice);
        static::assertCount(1, $identities);
        static::assertSame($identities[0], $this->identities->find($this->tenant, self::PROVIDER, self::SUBJECT));
        static::assertSame(
            [
                'given_name' => 'Alice',
                'family_name' => 'Liddell',
                'email' => self::ADDRESS,
            ],
            $identities[0]->claims,
        );
    }

    /**
     * The act of the account: the subject of the person and the name of the provider, and nothing the
     * provider said of them.
     */
    #[Test]
    public function aFirstSignInAnnouncesThePersonCreated(): void
    {
        // Given
        $context = Fixtures::context();

        // When
        $alice = $this->signIn(context: $context);

        // Then
        $announced = $this->events->of(PersonProvisioned::class);
        static::assertCount(1, $announced);
        static::assertSame($this->tenant, $announced[0]->tenant);
        static::assertSame($alice->subject, $announced[0]->person);
        static::assertSame(self::PROVIDER, $announced[0]->provider);
        static::assertEquals($this->clock->now(), $announced[0]->occurredAt);
        static::assertSame($context, $announced[0]->context);
    }

    /**
     * The person, its source and its linked identity are one unit, kept all or none; the refusals come before
     * it, so a refused creation opens none.
     */
    #[Test]
    public function aFirstSignInWritesThePersonAndItsLinkedIdentityAsOneUnit(): void
    {
        // When
        $this->signIn();

        // Then
        static::assertSame(1, $this->writes->units);
    }

    /**
     * The acceptance of the issue: the person found again by its linked identity, and nothing created or
     * announced a second time.
     */
    #[Test]
    public function aSecondSignInCreatesNothing(): void
    {
        // Given
        $alice = $this->signIn();

        // When
        $again = $this->signIn();

        // Then
        static::assertSame($alice, $again);
        static::assertCount(1, $this->identities->of($alice));
        static::assertCount(1, $this->events->of(PersonProvisioned::class));
    }

    /**
     * The acceptance of the issue: what the source holds is written as the provider says it now, a claim it
     * no longer says cleared, and the snapshot is the last thing it said.
     */
    #[Test]
    public function aSecondSignInWritesWhatTheProviderSaysNow(): void
    {
        // Given
        $alice = $this->signIn();
        $this->clock->sleep(3600);

        // When
        $this->signIn('alice.liddell@acme.example', [
            'given_name' => 'Alicia',
        ]);

        // Then
        static::assertSame('alice.liddell@acme.example', $alice->email?->value);
        static::assertTrue($alice->emailVerified);
        static::assertEquals(new Profile(givenName: 'Alicia'), $alice->profile);
        static::assertEquals($this->clock->now(), $alice->updatedAt);
        static::assertSame(
            [
                'given_name' => 'Alicia',
                'email' => 'alice.liddell@acme.example',
            ],
            $this->identities->of($alice)[0]->claims,
        );
    }

    /**
     * What another source holds is not this provider's to write: a person a console created, and whom an
     * import linked to this provider, keeps what they are, and only the snapshot of the identity moves.
     */
    #[Test]
    public function aSignInThroughAProviderThatIsNotTheSourceOfThePersonRefreshesTheSnapshotOnly(): void
    {
        // Given
        $alice = $this->provisioner->create($this->tenant, 'alice', new EmailAddress('alice@home.example'));
        $this->linker->link($alice, self::PROVIDER, self::SUBJECT);

        // When
        $this->signIn();

        // Then
        static::assertSame('alice@home.example', $alice->email?->value);
        static::assertFalse($alice->emailVerified);
        static::assertEquals(Profile::empty(), $alice->profile);
        static::assertSame(
            [
                'given_name' => 'Alice',
                'family_name' => 'Liddell',
                'email' => self::ADDRESS,
            ],
            $this->identities->of($alice)[0]->claims,
        );
    }

    /**
     * The acceptance of the issue, decision 0029: a provider never creates a person of a domain it does not
     * answer for.
     */
    #[Test]
    public function anAddressOutsideTheDomainsOfTheProviderIsRefused(): void
    {
        // Then
        $this->expectException(UpstreamProvisioningRefusedException::class);
        $this->expectExceptionMessageIs('The upstream provider "https://idp.acme.example/saml" does not answer for the domain "initech.example".');

        // When
        $this->signIn('alice@initech.example');
    }

    /**
     * The acceptance of the issue: no existing account is linked on its own, linking one being spike 12's,
     * after a local re-authentication. The address is matched as its blind index matches it, the domain
     * folded.
     */
    #[Test]
    #[DataProvider('provideAddressesBobHolds')]
    public function anAddressAnotherPersonHoldsIsRefused(string $address): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);

        // Then
        $this->expectException(UpstreamProvisioningRefusedException::class);
        $this->expectExceptionMessageIs('Another person of this tenant holds the address the upstream provider "https://idp.acme.example/saml" gave, and no existing account is linked to it on its own.');

        // When
        $this->signIn($address);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAddressesBobHolds(): iterable
    {
        yield 'as it was written' => ['bob@acme.example'];
        yield 'its domain in another case' => ['bob@ACME.example'];
    }

    /**
     * A refusal is raised before the first write: nobody is created, nothing is linked, nothing announced.
     *
     * @param array<string, string> $claims
     */
    #[Test]
    #[DataProvider('provideRefusedFirstSignIns')]
    public function aRefusedFirstSignInCreatesNobody(string $address, array $claims): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);

        // When
        try {
            $this->signIn($address, $claims);
        } catch (InvalidArgumentException|UpstreamProvisioningRefusedException) {
        }

        // Then
        static::assertNull($this->identities->find($this->tenant, self::PROVIDER, self::SUBJECT));
        static::assertNull($this->users->findByUsername($this->tenant, $address));
        static::assertSame([], $this->events->events);
        static::assertSame(0, $this->writes->units);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideRefusedFirstSignIns(): iterable
    {
        yield 'outside the domains of the provider' => ['alice@initech.example', []];
        yield 'held by another person' => ['bob@acme.example', []];
        yield 'a claim the profile refuses' => [
            self::ADDRESS,
            [
                'given_name' => 'Alice',
                'family_name' => 'Liddell',
                'birthdate' => 'the first of May',
            ],
        ];
    }

    /**
     * Refused before the lookup: an empty subject matches no row, and a person created for it would be left
     * without the linked identity that refuses it.
     */
    #[Test]
    public function anEmptySubjectIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A person an upstream provider names carries the subject it gave.');

        // When
        $this->provisioning->personNamedBy($this->tenant, $this->provider, '', new EmailAddress(self::ADDRESS), [], Fixtures::context());
    }

    /**
     * Decision 0029 at the next sign-ins too: what the provider writes of a person keeps to its domains and
     * to an address nobody else holds, and a refusal writes nothing, the snapshot included.
     */
    #[Test]
    #[DataProvider('provideAddressesASecondSignInCannotWrite')]
    public function aSecondSignInThatWouldWriteAnAddressTheProviderCannotWriteIsRefused(string $address, string $message): void
    {
        // Given
        $this->provisioner->create($this->tenant, 'bob', new EmailAddress('bob@acme.example'), true);
        $this->signIn();

        // Then
        $this->expectException(UpstreamProvisioningRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->signIn($address);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideAddressesASecondSignInCannotWrite(): iterable
    {
        yield 'outside the domains of the provider' => [
            'alice@initech.example',
            'The upstream provider "https://idp.acme.example/saml" does not answer for the domain "initech.example".',
        ];
        yield 'held by another person' => [
            'bob@acme.example',
            'Another person of this tenant holds the address the upstream provider "https://idp.acme.example/saml" gave, and no existing account is linked to it on its own.',
        ];
    }

    #[Test]
    public function aRefusedSecondSignInWritesNothing(): void
    {
        // Given
        $alice = $this->signIn();

        // When
        try {
            $this->signIn('alice@initech.example', [
                'given_name' => 'Alicia',
            ]);
        } catch (UpstreamProvisioningRefusedException) {
        }

        // Then
        static::assertSame(self::ADDRESS, $alice->email?->value);
        static::assertEquals(new Profile(givenName: 'Alice', familyName: 'Liddell'), $alice->profile);
        static::assertSame(self::ADDRESS, $this->identities->of($alice)[0]->claims['email']);
    }

    /**
     * The person holds their own address, so somebody who shares it with them, which nothing forbids two
     * local persons, is not a reason to refuse them their own sign-in. Asked only of an address that changed.
     */
    #[Test]
    public function anAddressThePersonAlreadyHoldsIsNotAskedAgain(): void
    {
        // Given
        $alice = $this->signIn();
        $this->provisioner->create($this->tenant, 'alice-at-home', new EmailAddress(self::ADDRESS));

        // When
        $again = $this->signIn();

        // Then
        static::assertSame($alice, $again);
    }

    /**
     * An address the person holds in another case of its domain is still theirs: the blind index finds them,
     * and they are nobody else.
     */
    #[Test]
    public function anAddressThePersonHoldsInAnotherCaseOfItsDomainIsWritten(): void
    {
        // Given
        $alice = $this->signIn();

        // When
        $this->signIn('alice@ACME.example');

        // Then
        static::assertSame('alice@ACME.example', $alice->email?->value);
    }

    /**
     * A source writes what it holds and nothing else: one that does not hold the address neither writes it
     * nor asks it of the domains of the provider.
     */
    #[Test]
    public function aSourceThatDoesNotHoldTheAddressLeavesIt(): void
    {
        // Given
        $alice = $this->provisioner->create(
            $this->tenant,
            'alice',
            new EmailAddress('alice@home.example'),
            source: UserSource::upstream(self::PROVIDER, ['given_name']),
        );
        $this->linker->link($alice, self::PROVIDER, self::SUBJECT);

        // When
        $this->signIn('alice@initech.example');

        // Then
        static::assertSame('alice@home.example', $alice->email?->value);
        static::assertEquals(new Profile(givenName: 'Alice'), $alice->profile);
    }

    /**
     * @param array<string, string> $claims
     */
    private function signIn(
        string $address = self::ADDRESS,
        array $claims = [
            'given_name' => 'Alice',
            'family_name' => 'Liddell',
        ],
        ?RequestContext $context = null,
    ): User {
        return $this->provisioning->personNamedBy(
            $this->tenant,
            $this->provider,
            self::SUBJECT,
            new EmailAddress($address),
            $claims,
            $context ?? Fixtures::context(),
        );
    }
}
