<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Oidc\Tests\Fixture\ServedModes;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Authorization\Display;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * Architecture §4.3, §5.3
 */
final class DoctrineInteractionRepositoryTest extends DatabaseTestCase
{
    public const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    #[Test]
    public function anInteractionComesBackWithItsWholeRequest(): void
    {
        // Given
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
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid'), new Scope('profile')]),
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
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
            ServedModes::QUERY,
            null,
            ResourceIndicators::of(['https://cal.example.com/', 'https://contacts.example.com/']),
        );
        $id = Secrets::draw();
        self::interactions()->save(new Interaction($id, self::tenant(), $request, 'fr', self::now(), self::now()->modify('+10 minutes')));
        self::reload();

        // When
        $found = self::interactions()->find($id) ?? static::fail('The interaction was not stored.');

        // Then
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
        static::assertSame('oidc-demo', $parked->client->registration->clientId);
        static::assertTrue($parked->client->belongsTo($found->tenant));
        static::assertSame((string) $client->registration->redirectUris[0], (string) $parked->redirectUri);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $parked->scopes->all);
        static::assertSame(self::CHALLENGE, $parked->codeChallenge?->value);
        static::assertSame('S256', $parked->codeChallenge->method->name());
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
        static::assertSame('query', $parked->responseMode);
        static::assertSame(['https://cal.example.com/', 'https://contacts.example.com/'], $parked->resources?->values());
    }

    #[Test]
    public function aBareRequestComesBackBare(): void
    {
        // Given
        $client = self::client('native-app');
        $request = new AuthorizationRequest(
            $client,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid')]),
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
        );
        $id = Secrets::draw();
        self::interactions()->save(new Interaction($id, self::tenant(), $request, null, self::now(), self::now()->modify('+10 minutes')));
        self::reload();

        // When
        $found = self::interactions()->find($id) ?? static::fail('The interaction was not stored.');

        // Then
        $parked = $found->request;
        static::assertNull($found->locale);
        static::assertSame('native-app', $parked->client->registration->clientId);
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
        static::assertNull($parked->resources);
    }

    #[Test]
    public function theSessionTheConsentAndTheCompletionAreWrittenOnSave(): void
    {
        // Given
        $user = self::user();
        $session = self::session($user);
        $client = self::client();
        $consent = new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now());
        self::service('test.beffroi.consents', ConsentRepositoryInterface::class)->save($consent);
        $request = new AuthorizationRequest(
            $client,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid')]),
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
        );
        $interaction = new Interaction(Secrets::draw(), self::tenant(), $request, 'en', self::now(), self::now()->modify('+10 minutes'));
        self::interactions()->save($interaction);
        $interaction->authenticate($session, self::now()->modify('+1 minute'));
        $interaction->consent($consent, self::now()->modify('+2 minutes'));
        $interaction->complete(self::now()->modify('+3 minutes'));
        self::interactions()->save($interaction);
        self::reload();

        // When
        $found = self::interactions()->find($interaction->id) ?? static::fail('The interaction was not stored.');

        // Then
        static::assertTrue($found->session?->id->equals($session->id));
        static::assertTrue($found->session->user->id->equals($user->id));
        static::assertTrue($found->consent?->id->equals($consent->id));
        static::assertSame('oidc-demo', $found->consent->client->registration->clientId);
        static::assertEquals(self::now()->modify('+3 minutes'), $found->completedAt);
        static::assertTrue($found->isCompleted());
    }

    #[Test]
    public function anInteractionOfAnUnregisteredClientIsNotFound(): void
    {
        // Given
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        $request = new AuthorizationRequest(
            $ghost,
            $ghost->registration->redirectUris[0],
            new Scopes([new Scope('openid')]),
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
        );
        $id = Secrets::draw();
        self::interactions()->save(new Interaction($id, self::tenant(), $request, null, self::now(), self::now()->modify('+10 minutes')));
        self::reload();

        // When / Then
        static::assertNull(self::interactions()->find($id));
    }

    #[Test]
    public function anUnknownIdentifierFindsNoInteraction(): void
    {
        // When / Then
        static::assertNull(self::interactions()->find(Secrets::draw()));
    }

    private static function interactions(): InteractionRepositoryInterface
    {
        return self::service('test.beffroi.interactions', InteractionRepositoryInterface::class);
    }
}
