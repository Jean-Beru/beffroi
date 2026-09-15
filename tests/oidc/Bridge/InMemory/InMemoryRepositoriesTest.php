<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\InMemory;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryRefreshTokenRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    #[Test]
    public function anEmptyInteractionRepositoryHasNoLastInteraction(): void
    {
        // When / Then
        static::assertNull(new InMemoryInteractionRepository()->last());
    }

    #[Test]
    public function itFindsAnInteractionByIdentifier(): void
    {
        // Given
        $repository = new InMemoryInteractionRepository();
        $first = $this->interaction();
        $second = $this->interaction();
        $repository->save($first);
        $repository->save($second);

        // When / Then
        static::assertSame($first, $repository->find($first->id));
        static::assertSame($second, $repository->find($second->id));
        static::assertNull($repository->find(Interaction::generateId()));
    }

    #[Test]
    public function theLastInteractionSavedIsTheLast(): void
    {
        // Given
        $repository = new InMemoryInteractionRepository();
        $first = $this->interaction();
        $second = $this->interaction();

        // When
        $repository->save($first);
        $repository->save($second);
        $repository->save($first);

        // Then
        static::assertSame($second, $repository->last());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function anEmptyConsentRepositoryHasNoActiveConsent(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();

        // When / Then
        static::assertNull($repository->findActive($this->session->user, $this->client));
    }

    /**
     * The consent in force is the active one granted last, for this user and this client only.
     */
    #[Test]
    public function itFindsTheActiveConsentGrantedLast(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $older = $this->consent($alice, $this->client, '-2 days');
        $newer = $this->consent($alice, $this->client, '-1 day');
        $revoked = $this->consent($alice, $this->client, '+0 seconds');
        $revoked->revoke(Fixtures::now());
        foreach ([$newer, $older, $revoked] as $consent) {
            $repository->save($consent);
        }

        // When / Then
        static::assertSame($newer, $repository->findActive($alice, $this->client));
    }

    #[Test]
    public function theConsentOfAnotherUserOrClientIsNotFound(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $alice = $this->session->user;
        $bob = Fixtures::user($alice->tenant, 'bob', 'bob-subject');
        $another = Clients::public($alice->tenant, 'another');
        $bobs = $this->consent($bob, $this->client, '+0 seconds');
        $repository->save($bobs);
        $repository->save($this->consent($alice, $another, '+0 seconds'));

        // When / Then
        static::assertSame($bobs, $repository->findActive($bob, $this->client));
        static::assertNull($repository->findActive($bob, $another));
    }

    #[Test]
    public function everyConsentSavedIsKept(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();

        // When
        foreach (['-2 days', '-1 day', '+0 seconds'] as $grantedAt) {
            $repository->save($this->consent($this->session->user, $this->client, $grantedAt));
        }

        // Then
        static::assertCount(3, $repository->all());
        static::assertSame(3, $repository->saves);
    }

    #[Test]
    public function betweenTwoConsentsGrantedAtTheSameInstantTheLastSavedWins(): void
    {
        // Given
        $repository = new InMemoryConsentRepository();
        $repository->save($this->consent($this->session->user, $this->client, '-1 day'));
        $tie = $this->consent($this->session->user, $this->client, '-1 day');

        // When
        $repository->save($tie);

        // Then
        static::assertSame($tie, $repository->findActive($this->session->user, $this->client));
    }

    #[Test]
    public function anEmptyCodeRepositoryFindsNothing(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();

        // When / Then
        static::assertSame([], $repository->all());
        static::assertNull($repository->findByCodeHash(AuthorizationCode::hash('one')));
    }

    #[Test]
    public function itKeepsEachCodeOnceByHash(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');

        // When
        $repository->save($code);
        $repository->save($code);

        // Then
        static::assertSame([$code], $repository->all());
        static::assertSame(2, $repository->saves);
    }

    #[Test]
    public function itFindsACodeByHashNeverByValue(): void
    {
        // Given
        $repository = new InMemoryAuthorizationCodeRepository();
        $code = $this->code('one');
        $repository->save($code);

        // When / Then
        static::assertSame($code, $repository->findByCodeHash(AuthorizationCode::hash('one')));
        static::assertNull($repository->findByCodeHash(AuthorizationCode::hash('two')));
        static::assertNull($repository->findByCodeHash('one'), 'the lookup is by hash, never by value');
    }

    #[Test]
    public function anEmptyRefreshTokenRepositoryFindsNothing(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), 'first-code');

        // When / Then
        static::assertSame([], $repository->all());
        static::assertNull($repository->findByTokenHash(RefreshToken::hash('first')));
        static::assertSame([], $repository->findByFamily($family->id));
        static::assertSame([], $repository->findByAuthorizationCode(AuthorizationCode::hash('first-code')));
        static::assertSame([], $repository->findBySession($this->session->id));
    }

    /**
     * Architecture §4.6: a token is found by its hash, never by its value.
     */
    #[Test]
    public function itFindsARefreshTokenByHashNeverByValue(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $repository->save($first);

        // When / Then
        static::assertSame($first, $repository->findByTokenHash(RefreshToken::hash('first')));
        static::assertNull($repository->findByTokenHash('first'), 'the lookup is by hash, never by value');
        static::assertNull($repository->findByTokenHash(RefreshToken::hash('unknown')));
    }

    /**
     * Architecture §4.6: a family is found whole, whatever the state of its members.
     */
    #[Test]
    public function itFindsAFamilyWhole(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), 'first-code');
        $lineage = $this->lineage($family);
        $other = Tokens::refreshToken('other', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), 'other-code'));
        foreach ([...$lineage, $other] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByFamily($family->id));
        static::assertSame([$other], $repository->findByFamily($other->family->id));
        static::assertSame([], $repository->findByFamily(Uuid::v7()));
    }

    /**
     * Architecture §4.6: the descendants of a code are the family.
     */
    #[Test]
    public function itFindsTheDescendantsOfACode(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $family = Tokens::family(Fixtures::now(), 'first-code');
        $lineage = $this->lineage($family);
        $other = Tokens::refreshToken('other', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), 'other-code'));
        foreach ([...$lineage, $other] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame($lineage, $repository->findByAuthorizationCode(AuthorizationCode::hash('first-code')));
        static::assertSame([$other], $repository->findByAuthorizationCode(AuthorizationCode::hash('other-code')));
        static::assertSame([], $repository->findByAuthorizationCode(AuthorizationCode::hash('unknown')));
    }

    /**
     * Architecture §4.9: the tokens of a session are found whole, rotated and revoked ones included.
     */
    #[Test]
    public function itFindsEveryTokenOfASession(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $lineage = $this->lineage(Tokens::family(Fixtures::now(), 'first-code'));
        $other = Tokens::refreshToken('other', $this->client, $this->session, Fixtures::now(), Tokens::family(Fixtures::now(), 'other-code'));
        $elsewhere = Tokens::refreshToken('elsewhere', $this->client, Fixtures::session(Fixtures::user($this->session->tenant, 'bob', 'bob-subject')), Fixtures::now());
        foreach ([...$lineage, $other, $elsewhere] as $token) {
            $repository->save($token);
        }

        // When / Then
        static::assertSame([...$lineage, $other], $repository->findBySession($this->session->id));
        static::assertSame([$elsewhere], $repository->findBySession($elsewhere->session->id));
        static::assertSame([], $repository->findBySession(Uuid::v7()));
    }

    #[Test]
    public function itKeepsEachRefreshTokenOnce(): void
    {
        // Given
        $repository = new InMemoryRefreshTokenRepository();
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now());
        $second = Tokens::refreshToken('second', $this->client, $this->session, Fixtures::now());

        // When
        foreach ([$first, $second, $first] as $token) {
            $repository->save($token);
        }

        // Then
        static::assertSame([$first, $second], $repository->all());
        static::assertSame(3, $repository->saves);
    }

    private function interaction(): Interaction
    {
        return new Interaction(Interaction::generateId(), $this->client->tenant, Requests::authorization($this->client), null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    private function consent(User $user, Client $client, string $grantedAt): Consent
    {
        return new Consent(Uuid::v7(), $user, $client, [Scope::openid()], Fixtures::now()->modify($grantedAt));
    }

    private function code(string $value): AuthorizationCode
    {
        return new AuthorizationCode(AuthorizationCode::hash($value), $this->client, $this->session, $this->client->redirectUris[0], [Scope::openid()], null, new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256), null, Fixtures::now(), ['pwd'], null, Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
    }

    /**
     * A first token rotated into a second, then a revoked one, in the family given.
     *
     * @return list<RefreshToken>
     */
    private function lineage(RefreshTokenFamily $family): array
    {
        $first = Tokens::refreshToken('first', $this->client, $this->session, Fixtures::now(), $family);
        $second = Tokens::refreshToken('second', $this->client, $this->session, Fixtures::now()->modify('+1 day'), $family);
        $first->rotate(Fixtures::now()->modify('+1 day'));
        $revoked = Tokens::refreshToken('revoked', $this->client, $this->session, Fixtures::now()->modify('+2 days'), $family);
        $revoked->revoke(Fixtures::now()->modify('+2 days'));

        return [$first, $second, $revoked];
    }
}
