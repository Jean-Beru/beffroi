<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Disclosure;

use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Disclosure\DisclosureRecording;
use Beffroi\Oidc\Bridge\InMemory\InMemoryDisclosures;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetail;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Uid\UuidV7;

final class DisclosureRecordingTest extends TestCase
{
    private InMemoryDisclosures $disclosures;

    private DisclosureRecording $recording;

    private AuthenticationSession $session;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->disclosures = new InMemoryDisclosures();
        $this->recording = new DisclosureRecording($this->disclosures, new SymfonyUuidGenerator());
    }

    #[Test]
    public function itWritesDownWhatTheActGaveTheClient(): void
    {
        // Given
        $act = $this->act();

        // When
        $this->recording->record($act);

        // Then
        $written = $this->disclosures->all()[0] ?? static::fail('Nothing was written down.');
        static::assertSame('oidc-demo', $written->clientId);
        static::assertTrue($written->subject->equals($this->session->user->subject));
        static::assertSame(TokensIssued::NAME, $written->act);
        static::assertEquals($act->occurredAt, $written->handedOverAt);
        static::assertSame(['openid', 'email'], $written->scopes->values());
        static::assertSame(['userinfo' => ['email'], 'id_token' => []], $written->claims?->names());
        static::assertSame([['type' => 'urn:example:payment']], $written->details?->toClaim());
        static::assertSame('jwt', $written->tokenShape);
    }

    #[Test]
    public function itDrawsTheIdentifierOfTheRow(): void
    {
        // When
        $this->recording->record($this->act());

        // Then
        static::assertInstanceOf(UuidV7::class, ($this->disclosures->all()[0] ?? static::fail('Nothing was written down.'))->id);
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function anActThatNamesNobodyWritesNothingDown(): void
    {
        // Given
        $act = $this->act(naming: false);

        // When
        $this->recording->record($act);

        // Then
        static::assertSame([], $this->disclosures->all());
    }

    private function act(bool $naming = true): TokensIssued
    {
        return new TokensIssued(
            Fixtures::now(),
            $this->session->tenant,
            Grants::authorizationCode(),
            Uuid::v7(),
            'oidc-demo',
            $naming ? $this->session->user->subject : null,
            $this->session->id,
            new Scopes([Scope::openid(), new Scope('email')]),
            Fixtures::now()->modify('+10 minutes'),
            true,
            null,
            null,
            new ClaimsRequest([
                'email' => new ClaimRequest(),
            ]),
            new AuthorizationDetails([new AuthorizationDetail('urn:example:payment')]),
            'jwt',
            Fixtures::context(),
        );
    }
}
