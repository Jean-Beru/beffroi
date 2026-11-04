<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Ciba;

use Beffroi\Core\Bridge\InMemory\InMemoryUserRepository;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Hint\SubjectLoginHint;
use Beffroi\Oidc\Application\Hint\UsernameLoginHint;
use Beffroi\Oidc\Application\Ciba\UserHints;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\TestCase;

/**
 * CIBA Core §7.1
 */
final class UserHintsTest extends TestCase
{
    private Client $client;

    private User $alice;

    private InMemoryUserRepository $users;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::backchannel($tenant, new FakePasswordHasher()->hash(Clients::SECRET));
        $this->alice = Fixtures::user($tenant);
        $this->users = new InMemoryUserRepository();
        $this->users->save($this->alice);
    }

    /**
     * CIBA Core §15
     */
    #[Test]
    public function aLoginHintReadAsASubjectNamesItsUser(): void
    {
        // Given
        $hints = new UserHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // When
        $user = $hints->userNamedBy($this->client, RequestParameters::of([
            'login_hint' => 'alice-subject',
        ]));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * CIBA Core §7.1
     */
    #[Test]
    public function aLoginHintReadAsAUsernameNamesItsUser(): void
    {
        // Given
        $hints = new UserHints([new UsernameLoginHint($this->users)]);

        // When
        $user = $hints->userNamedBy($this->client, RequestParameters::of([
            'login_hint' => 'alice',
        ]));

        // Then
        static::assertSame($this->alice, $user);
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideHintsNamingNobody')]
    public function aHintThatNamesNobodyIsNoError(string $value): void
    {
        // Given
        $hints = new UserHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // When
        $user = $hints->userNamedBy($this->client, RequestParameters::of([
            'login_hint' => $value,
        ]));

        // Then
        static::assertNull($user);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHintsNamingNobody(): iterable
    {
        yield 'a subject nobody has' => ['bob-subject'];
        yield 'a value that is no subject at all' => ["\x00"];
    }

    /**
     * CIBA Core §7.1
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideRequestsNamingTheUserOnceOrNotAtAll')]
    public function aRequestNamesItsUserOnce(array $parameters): void
    {
        // Given
        $hints = new UserHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: A backchannel authentication request names the user it is made for once, by one of login_hint_token, id_token_hint and login_hint (CIBA Core section 7.1).');

        // When
        $hints->userNamedBy($this->client, RequestParameters::of($parameters));
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideRequestsNamingTheUserOnceOrNotAtAll(): iterable
    {
        yield 'no hint at all' => [[]];
        yield 'two hints' => [['login_hint' => 'alice-subject', 'id_token_hint' => 'eyJ.the.token']];
        yield 'a hint this provider reads and one it does not' => [['login_hint' => 'alice-subject', 'login_hint_token' => 'eyJ.the.token']];
    }

    #[Test]
    public function aHintNothingIsWiredToReadIsRefused(): void
    {
        // Given
        $hints = new UserHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);

        // Then
        $this->expectException(InvalidRequestException::class);
        $this->expectExceptionMessageIs('invalid_request: This provider does not read the login_hint_token parameter of a backchannel authentication request (CIBA Core section 7.1).');

        // When
        $hints->userNamedBy($this->client, RequestParameters::of([
            'login_hint_token' => 'eyJ.the.token',
        ]));
    }

    #[Test]
    public function aParameterIsReadOneWay(): void
    {
        // Given
        $hints = new UserHints([new SubjectLoginHint(Subjects::ofAProvider($this->users)), new UsernameLoginHint($this->users)]);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Two hints are wired to read the login_hint parameter of a backchannel authentication request; a hint is read one way.');

        // When
        $hints->userNamedBy($this->client, RequestParameters::of([
            'login_hint' => 'alice-subject',
        ]));
    }

    #[Test]
    public function aHintOfAnotherTenantNamesNobody(): void
    {
        // Given
        $hints = new UserHints([new SubjectLoginHint(Subjects::ofAProvider($this->users))]);
        $other = Clients::backchannel(
            Fixtures::tenant('other', 'https://id.other.example'),
            new FakePasswordHasher()->hash(Clients::SECRET),
        );

        // When
        $user = $hints->userNamedBy($other, RequestParameters::of([
            'login_hint' => 'alice-subject',
        ]));

        // Then
        static::assertNull($user);
    }
}
