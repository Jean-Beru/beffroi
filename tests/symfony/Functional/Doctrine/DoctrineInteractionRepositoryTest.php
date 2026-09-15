<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\Display;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.3, §5.3: an interaction parks a validated request, every parameter of it, and comes
 * back with the client the configuration registers under the identifier the row keeps.
 */
final class DoctrineInteractionRepositoryTest extends DatabaseTestCase
{
    public const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    #[Test]
    public function anInteractionComesBackWithItsWholeRequest(): void
    {
        $interactions = self::interactions();
        $client = self::client();
        $claims = new ClaimsRequest([
            'email' => new ClaimRequest(true),
            'name' => new ClaimRequest(),
        ], [
            'acr' => new ClaimRequest(false, null, ['urn:example:acr:silver', 'urn:example:acr:gold']),
            'auth_time' => new ClaimRequest(true, 1789000000),
        ]);
        $request = new AuthorizationRequest(
            $client,
            $client->redirectUris[0],
            [new Scope('openid'), new Scope('profile')],
            new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256),
            'af0ifjsldkj',
            'n-0S6_WzA2Mj',
            [Prompt::Login, Prompt::Consent],
            3600,
            'alice@example.com',
            ['fr-CA', 'fr', 'en'],
            ['urn:example:acr:gold'],
            Display::Page,
            'eyJhbGciOiJSUzI1NiJ9.e30.sig',
            $claims,
            ResponseMode::Query,
        );
        $id = Interaction::generateId();
        $interactions->save(new Interaction($id, self::tenant(), $request, 'fr', self::now(), self::now()->modify('+10 minutes')));
        self::reload();

        $found = $interactions->find($id) ?? static::fail('The interaction was not stored.');

        static::assertSame($id, $found->id);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('fr', $found->locale);
        static::assertEquals(self::now(), $found->createdAt);
        static::assertEquals(self::now()->modify('+10 minutes'), $found->expiresAt);
        static::assertNull($found->session);
        static::assertNull($found->consent);
        static::assertNull($found->completedAt);
        $parked = $found->request;
        static::assertSame('oidc-demo', $parked->client->clientId);
        static::assertTrue($parked->client->belongsTo($found->tenant));
        static::assertSame((string) $client->redirectUris[0], (string) $parked->redirectUri);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $parked->scopes);
        static::assertSame(self::CHALLENGE, $parked->codeChallenge->value);
        static::assertSame('S256', $parked->codeChallenge->method->value);
        static::assertSame('af0ifjsldkj', $parked->state);
        static::assertSame('n-0S6_WzA2Mj', $parked->nonce);
        static::assertSame([Prompt::Login, Prompt::Consent], $parked->prompts);
        static::assertSame(3600, $parked->maxAge);
        static::assertSame('alice@example.com', $parked->loginHint);
        static::assertSame(['fr-CA', 'fr', 'en'], $parked->uiLocales);
        static::assertSame(['urn:example:acr:gold'], $parked->acrValues);
        static::assertSame(Display::Page, $parked->display);
        static::assertSame('eyJhbGciOiJSUzI1NiJ9.e30.sig', $parked->idTokenHint);
        static::assertEquals($claims, $parked->claims);
        static::assertSame('query', $parked->responseMode->value);
    }

    #[Test]
    public function aBareRequestComesBackBare(): void
    {
        $interactions = self::interactions();
        $client = self::client('native-app');
        $request = new AuthorizationRequest($client, $client->redirectUris[0], [new Scope('openid')], new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256));
        $id = Interaction::generateId();
        $interactions->save(new Interaction($id, self::tenant(), $request, null, self::now(), self::now()->modify('+10 minutes')));
        self::reload();

        $found = $interactions->find($id) ?? static::fail('The interaction was not stored.');
        $parked = $found->request;

        static::assertNull($found->locale);
        static::assertSame('native-app', $parked->client->clientId);
        static::assertNull($parked->state);
        static::assertNull($parked->nonce);
        static::assertSame([], $parked->prompts);
        static::assertNull($parked->maxAge);
        static::assertNull($parked->loginHint);
        static::assertSame([], $parked->uiLocales);
        static::assertSame([], $parked->acrValues);
        static::assertNull($parked->display);
        static::assertNull($parked->idTokenHint);
        static::assertNull($parked->claims);
    }

    #[Test]
    public function theSessionTheConsentAndTheCompletionAreWrittenOnSave(): void
    {
        $interactions = self::interactions();
        $user = self::user();
        $session = self::session($user);
        $client = self::client();
        $consent = new Consent(Uuid::v7(), $user, $client, [new Scope('openid')], self::now());
        self::service('test.heidi.consents', ConsentRepositoryInterface::class)
            ->save($consent);
        $request = new AuthorizationRequest($client, $client->redirectUris[0], [new Scope('openid')], new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256));
        $interaction = new Interaction(Interaction::generateId(), self::tenant(), $request, 'en', self::now(), self::now()->modify('+10 minutes'));
        $interactions->save($interaction);
        $interaction->authenticate($session, self::now()->modify('+1 minute'));
        $interaction->consent($consent, self::now()->modify('+2 minutes'));
        $interaction->complete(self::now()->modify('+3 minutes'));
        $interactions->save($interaction);
        self::reload();

        $found = $interactions->find($interaction->id) ?? static::fail('The interaction was not stored.');

        static::assertTrue($found->session?->id->equals($session->id));
        static::assertTrue($found->session->user->id->equals($user->id));
        static::assertTrue($found->consent?->id->equals($consent->id));
        static::assertSame('oidc-demo', $found->consent->client->clientId);
        static::assertEquals(self::now()->modify('+3 minutes'), $found->completedAt);
        static::assertTrue($found->isCompleted());
    }

    /**
     * A client removed from the configuration leaves its interactions without a client: nothing can
     * resume them, they are not found.
     */
    #[Test]
    public function anInteractionOfAnUnregisteredClientIsNotFound(): void
    {
        $interactions = self::interactions();
        $ghost = new Client(self::tenant(), 'ghost', 'Removed client', TokenEndpointAuthMethod::None, null, [new RedirectUri('https://ghost.example/callback')]);
        $request = new AuthorizationRequest($ghost, $ghost->redirectUris[0], [new Scope('openid')], new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256));
        $id = Interaction::generateId();
        $interactions->save(new Interaction($id, self::tenant(), $request, null, self::now(), self::now()->modify('+10 minutes')));
        self::reload();

        static::assertNull($interactions->find($id));
        static::assertNull($interactions->find(Interaction::generateId()));
    }

    private static function interactions(): InteractionRepositoryInterface
    {
        return self::service('test.heidi.interactions', InteractionRepositoryInterface::class);
    }
}
