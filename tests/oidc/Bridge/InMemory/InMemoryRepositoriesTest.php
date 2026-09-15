<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\InMemory;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\InMemory\InMemoryAuthorizationCodeRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryConsentRepository;
use Heidi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class InMemoryRepositoriesTest extends TestCase
{
    #[Test]
    public function itFindsAnInteractionByIdentifier(): void
    {
        $repository = new InMemoryInteractionRepository();
        $client = Clients::public(Fixtures::tenant());
        $first = new Interaction(Interaction::generateId(), $client->tenant, Requests::authorization($client), null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $second = new Interaction(Interaction::generateId(), $client->tenant, Requests::authorization($client), null, Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        static::assertNull($repository->last());
        $repository->save($first);
        $repository->save($second);
        $repository->save($first);

        static::assertSame($first, $repository->find($first->id));
        static::assertSame($second, $repository->find($second->id));
        static::assertNull($repository->find(Interaction::generateId()));
        static::assertSame($second, $repository->last());
        static::assertSame(3, $repository->saves);
    }

    /**
     * The consent in force is the active one granted last, for this user and this client only.
     */
    #[Test]
    public function itFindsTheActiveConsentGrantedLast(): void
    {
        $repository = new InMemoryConsentRepository();
        $alice = Fixtures::user();
        $bob = Fixtures::user($alice->tenant, 'bob', 'bob-subject');
        $client = Clients::public($alice->tenant);
        $older = new Consent(Uuid::v7(), $alice, $client, [Scope::openid()], Fixtures::now()->modify('-2 days'));
        $newer = new Consent(Uuid::v7(), $alice, $client, [Scope::openid()], Fixtures::now()->modify('-1 day'));
        $revoked = new Consent(Uuid::v7(), $alice, $client, [Scope::openid()], Fixtures::now());
        $revoked->revoke(Fixtures::now());
        $bobs = new Consent(Uuid::v7(), $bob, $client, [Scope::openid()], Fixtures::now());
        $elsewhere = new Consent(Uuid::v7(), $alice, Clients::public($alice->tenant, 'another'), [Scope::openid()], Fixtures::now());

        static::assertNull($repository->findActive($alice, $client));
        foreach ([$newer, $older, $revoked, $bobs, $elsewhere] as $consent) {
            $repository->save($consent);
        }

        static::assertSame($newer, $repository->findActive($alice, $client));
        static::assertSame($bobs, $repository->findActive($bob, $client));
        static::assertNull($repository->findActive($bob, Clients::public($alice->tenant, 'another')));
        static::assertCount(5, $repository->all());
        static::assertSame(5, $repository->saves);

        $tie = new Consent(Uuid::v7(), $alice, $client, [Scope::openid()], Fixtures::now()->modify('-1 day'));
        $repository->save($tie);

        static::assertSame($tie, $repository->findActive($alice, $client));
    }

    #[Test]
    public function itKeepsEachCodeOnceByHash(): void
    {
        $repository = new InMemoryAuthorizationCodeRepository();
        $session = Fixtures::session();
        $client = Clients::public($session->tenant);
        $code = new AuthorizationCode(AuthorizationCode::hash('one'), $client, $session, $client->redirectUris[0], [Scope::openid()], null, new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256), null, Fixtures::now(), ['pwd'], null, Fixtures::now(), Fixtures::now()->modify('+60 seconds'));

        static::assertSame([], $repository->all());
        $repository->save($code);
        $repository->save($code);

        static::assertSame([$code], $repository->all());
    }
}
