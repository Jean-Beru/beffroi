<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Hint;

use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Consent\SharedIdentity;
use Beffroi\Oidc\Application\Hint\LoginHints;
use Beffroi\Oidc\Application\Hint\SubjectLoginHint;
use Beffroi\Oidc\Application\Hint\UserHintInterface;
use Beffroi\Oidc\Application\Hint\UsernameLoginHint;
use Beffroi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryPairwiseSubjectRepository;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §3.1.2.1, §4
 */
final class LoginHintsTest extends TestCase
{
    private Client $client;

    private User $alice;

    private InMemoryUserRepository $users;

    private InMemoryConsentRepository $consents;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::public($tenant);
        $this->alice = Fixtures::user($tenant);
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
        $this->consents = new InMemoryConsentRepository();
        $this->consentTo($this->client);
    }

    /**
     * OIDC Core §8, §4
     */
    #[Test]
    public function aHintReadAsASubjectNamesItsUser(): void
    {
        // Given
        $hints = $this->hints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function aHintReadAsAUsernameNamesItsUser(): void
    {
        // Given
        $hints = $this->hints([new UsernameLoginHint($this->users)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice'));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    #[DataProvider('provideHintsNamingNobody')]
    public function aHintThatNamesNobodyNamesNobody(?string $value): void
    {
        // Given
        $hints = $this->hints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: $value));

        // Then
        static::assertNull($user);
    }

    /**
     * @return iterable<string, array{string|null}>
     */
    public static function provideHintsNamingNobody(): iterable
    {
        yield 'a request that carries no hint' => [null];
        yield 'a hint that carries nothing' => [''];
        yield 'a subject nobody has' => ['bob-subject'];
        yield 'a value that is no subject at all' => ["\x00"];
    }

    #[Test]
    public function aHintNothingIsWiredToReadNamesNobody(): void
    {
        // Given
        $hints = $this->hints([]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));

        // Then
        static::assertNull($user);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function aReadingThatRefusesTheValueNamesNobody(): void
    {
        // Given
        $refusing = self::createStub(UserHintInterface::class);
        $refusing->method('parameterName')->willReturn(LoginHints::PARAMETER);
        $refusing->method('userNamedBy')->willThrowException(new InvalidRequestException('Not of the shape I read.'));

        // When
        $user = $this->hints([$refusing])->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));

        // Then
        static::assertNull($user);
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function twoReadingsOfOneParameterAreRefused(): void
    {
        // Given
        $hints = $this->hints([
            new SubjectLoginHint(Subjects::ofAProvider($this->users)),
            new UsernameLoginHint($this->users),
        ]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Two hints are wired to read the login_hint parameter of an authorization request; a hint is read one way.');

        // When
        $hints->userNamedBy(Requests::authorization($this->client, loginHint: 'alice-subject'));
    }

    /**
     * OIDC Core §8.1, §4
     */
    #[Test]
    public function aPairwiseHintNamesItsUserForTheClientItWasHandedTo(): void
    {
        // Given
        $assigned = new InMemoryPairwiseSubjectRepository();
        $subjects = Subjects::bothKinds($this->users, assigned: $assigned);
        $sector = Clients::pairwise($this->alice->tenant, 'pairwise-app', 'https://rp.example/callback');
        $this->consentTo($sector);
        $hints = $this->hints([new SubjectLoginHint($subjects)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($sector, loginHint: $subjects->resolve($this->alice, $sector)->value));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function aPairwiseHintOfAnotherSectorNamesNobody(): void
    {
        // Given
        $assigned = new InMemoryPairwiseSubjectRepository();
        $subjects = Subjects::bothKinds($this->users, assigned: $assigned);
        $sector = Clients::pairwise($this->alice->tenant, 'pairwise-app', 'https://rp.example/callback');
        $other = Clients::pairwise($this->alice->tenant, 'pairwise-other-app', 'https://other.example/callback');
        $this->consentTo($other);
        $hints = $this->hints([new SubjectLoginHint($subjects)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization($other, loginHint: $subjects->resolve($this->alice, $sector)->value));

        // Then
        static::assertNull($user);
    }

    /**
     * OIDC Core §8, decision 0006
     *
     * @param callable(InMemoryUserRepository): UserHintInterface $reading
     */
    #[Test]
    #[DataProvider('provideHintsOfAPersonTheClientMayNotBeToldOf')]
    public function aHintOfAPersonWhoGaveTheClientNoConsentNamesNobody(callable $reading, string $value): void
    {
        // Given
        $hints = $this->hints([$reading($this->users)]);

        // When
        $user = $hints->userNamedBy(Requests::authorization(Clients::public($this->alice->tenant, 'another-spa'), loginHint: $value));

        // Then
        static::assertNull($user);
    }

    /**
     * @return iterable<string, array{callable(InMemoryUserRepository): UserHintInterface, string}>
     */
    public static function provideHintsOfAPersonTheClientMayNotBeToldOf(): iterable
    {
        yield 'her subject' => [
            static fn (InMemoryUserRepository $users): UserHintInterface => new SubjectLoginHint(Subjects::ofAProvider($users)),
            'alice-subject',
        ];
        yield 'her username' => [
            static fn (InMemoryUserRepository $users): UserHintInterface => new UsernameLoginHint($users),
            'alice',
        ];
    }

    /**
     * @param list<UserHintInterface> $readings
     */
    private function hints(array $readings): LoginHints
    {
        return new LoginHints($readings, new SharedIdentity($this->consents));
    }

    private function consentTo(Client $client): void
    {
        $this->consents->save(new Consent(Uuid::v7(), $this->alice, $client, new Scopes([Scope::openid()]), Fixtures::now()));
    }
}
