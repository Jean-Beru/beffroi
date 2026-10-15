<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\SingleSignOn;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Application\SingleSignOn\AttributeRelease;
use Beffroi\Saml\Application\SingleSignOn\SingleSignOn;
use Beffroi\Saml\Bridge\Configuration\ConfigurationServiceProviders;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Domain\SingleSignOn\SignOnStatus;
use Beffroi\Saml\Exception\SignOnRefusedException;
use Beffroi\Saml\Tests\Fixture\FixedClaims;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\FixedSalt;
use Beffroi\Saml\Tests\Fixture\GivenRequests;
use Beffroi\Saml\Tests\Fixture\RecordingLogger;
use Beffroi\Saml\Tests\Fixture\RecordingResponder;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use Closure;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.4: what a request accepted is answered with, from the session the browser holds, after a
 * login, or with a failure.
 */
final class SingleSignOnTest extends TestCase
{
    private const string ENCRYPTING = 'https://encrypting.example.org/saml';

    private Tenant $tenant;

    private MockClock $clock;

    private RecordingResponder $responder;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->clock = new MockClock(Fixtures::now());
        $this->responder = new RecordingResponder();
    }

    /**
     * S-17: a browser without a session signs in first.
     */
    #[Test]
    public function aBrowserWithoutASessionSignsInFirst(): void
    {
        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), null);

        // Then
        static::assertNull($form);
    }

    /**
     * S-17, Core §3.4.1: IsPassive without a session that answers is NoPassive, never a page.
     */
    #[Test]
    public function aPassiveRequestWithoutASessionIsNoPassive(): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(isPassive: true), null);

        // Then
        static::assertSame(SignOnStatus::NoPassive, $this->responder->failure?->status);
    }

    /**
     * Section 6.4 steps 5 to 7: an active session answers with the persistent identifier of its user at that service
     * provider, its attributes, its ID as the SessionIndex and its latest proof, issued now.
     */
    #[Test]
    public function anActiveSessionAnswers(): void
    {
        // Given
        $session = $this->session();
        $request = SignOnRequests::request();

        // When
        $form = $this->singleSignOn()->answer($this->tenant, $request, $session);

        // Then
        static::assertEquals(
            new SignOnResponse(
                'https://id.acme.example' . FixedEndpoints::METADATA,
                $request,
                PersistentNameId::derive(ServiceProviderDocuments::SIGNED, $session->user->subject, FixedSalt::SALT),
                [new ReleasedAttribute('urn:oid:0.9.2342.19200300.100.1.3', AttributeNameFormat::Uri, 'mail', [new AttributeValue('alice@example.com')])],
                $session->id->toRfc4122(),
                $session->authenticatedAt(),
                Fixtures::now(),
            ),
            $this->responder->response,
        );
        static::assertEquals(new PostedForm(SignOnRequests::ASSERTION_CONSUMER, ['SAMLResponse' => 'success']), $form);
    }

    /**
     * S-17, Core §3.4.1: ForceAuthn is not answered from a proof older than the request.
     */
    #[Test]
    public function aForcedRequestIsNotAnsweredFromAnOlderProof(): void
    {
        // Given
        $session = $this->session(Fixtures::now()->modify('-1 second'));

        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(forceAuthn: true), $session);

        // Then
        static::assertNull($form);
    }

    /**
     * S-17: ForceAuthn is answered from a proof made at or after the request was received.
     */
    #[Test]
    public function aForcedRequestIsAnsweredFromAProofMadeSinceIt(): void
    {
        // Given
        $session = $this->session(Fixtures::now());

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(forceAuthn: true), $session);

        // Then
        static::assertSame($session->id->toRfc4122(), $this->responder->response?->sessionIndex);
    }

    /**
     * S-17: a session that has ended, or one of another tenant, answers nothing.
     *
     * @param Closure(Tenant): AuthenticationSession $session
     */
    #[Test]
    #[DataProvider('provideSessionsThatDoNotAnswer')]
    public function aSessionThatDoesNotAnswerAsksForALogin(Closure $session): void
    {
        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $session($this->tenant));

        // Then
        static::assertNull($form);
    }

    /**
     * @return iterable<string, array{Closure(Tenant): AuthenticationSession}>
     */
    public static function provideSessionsThatDoNotAnswer(): iterable
    {
        yield 'ended' => [static function (Tenant $tenant): AuthenticationSession {
            $session = Fixtures::session(Fixtures::user($tenant));
            $session->end(SessionEnd::User, Fixtures::now());

            return $session;
        }];
        yield 'of another tenant' => [static fn (Tenant $tenant): AuthenticationSession => Fixtures::session(Fixtures::user(Fixtures::tenant('globex')))];
    }

    /**
     * Section 6.4 step 4, Core §3.4.1.1: a NameIDPolicy of another format is InvalidNameIDPolicy, whatever the session.
     */
    #[Test]
    public function aNameIdPolicyOfAnotherFormatIsRefused(): void
    {
        // When
        $this->singleSignOn()->answer(
            $this->tenant,
            SignOnRequests::request(nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'),
            $this->session(),
        );

        // Then
        static::assertSame(SignOnStatus::InvalidNameIdPolicy, $this->responder->failure?->status);
    }

    /**
     * Section 6.4 step 4: a NameIDPolicy of the persistent format, or of the unspecified one, is answered.
     */
    #[Test]
    #[DataProvider('provideAnsweredFormats')]
    public function aNameIdPolicyThePersistentIdentifierSatisfiesIsAnswered(string $format): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(nameIdFormat: $format), $this->session());

        // Then
        static::assertInstanceOf(SignOnResponse::class, $this->responder->response);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAnsweredFormats(): iterable
    {
        yield 'persistent' => ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'];
        yield 'unspecified' => ['urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'];
    }

    /**
     * Section 6.4 step 4, Core §3.3.2.2.1: a class of authentication context asked for is NoAuthnContext.
     */
    #[Test]
    public function aRequestedAuthenticationContextIsNoAuthnContext(): void
    {
        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(authnContextRequested: true), $this->session());

        // Then
        static::assertEquals(
            new SignOnFailure(
                'https://id.acme.example' . FixedEndpoints::METADATA,
                SignOnRequests::request(authnContextRequested: true),
                SignOnStatus::NoAuthnContext,
                Fixtures::now(),
            ),
            $this->responder->failure,
        );
    }

    /**
     * Section 6.4 step 4: what is never written is answered before anybody signs in.
     */
    #[Test]
    public function aFailureIsAnsweredBeforeALogin(): void
    {
        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(authnContextRequested: true), null);

        // Then
        static::assertEquals(new PostedForm(SignOnRequests::ASSERTION_CONSUMER, ['SAMLResponse' => 'failure']), $form);
    }

    /**
     * S-18, section 7: a request is answered within ten minutes of its receipt and refused after.
     */
    #[Test]
    public function aRequestThatWaitedTenMinutesIsRefused(): void
    {
        // Given
        $this->clock->modify('+600 seconds');

        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The request waited longer than the ten minutes it may wait for a login (spec/saml.md S-18).');

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $this->session());
    }

    /**
     * S-18: a second before its ten minutes, the request is answered.
     */
    #[Test]
    public function aRequestIsAnsweredWithinItsTenMinutes(): void
    {
        // Given
        $this->clock->modify('+599 seconds');

        // When
        $form = $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(), $this->session());

        // Then
        static::assertNotNull($form);
    }

    /**
     * S-7, section 6.4 step 2, issue #733: nothing is sent in clear to a service provider that asks for encryption.
     */
    #[Test]
    public function aServiceProviderThatAsksForEncryptionIsRefused(): void
    {
        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The service provider asks for its assertions encrypted, which this identity provider does not do yet: none is sent in clear (spec/saml.md S-7).');

        // When
        $this->singleSignOn(SignOnRequests::request(serviceProvider: self::ENCRYPTING))->receiveRedirect($this->tenant, 'SAMLRequest=x');
    }

    /**
     * Section 6.4 step 2: a declaration removed while the request waited answers nothing.
     */
    #[Test]
    public function aServiceProviderNoLongerDeclaredIsRefused(): void
    {
        // Then
        $this->expectException(SignOnRefusedException::class);
        $this->expectExceptionMessageIs('The service provider of the request is no longer declared (spec/saml.md section 6.4 step 2).');

        // When
        $this->singleSignOn()->answer($this->tenant, SignOnRequests::request(serviceProvider: 'https://gone.example.org/saml'), $this->session());
    }

    /**
     * Section 6.4 step 1: the request the receiver accepted over HTTP-POST, its service provider declared.
     */
    #[Test]
    public function aRequestPostedIsReceived(): void
    {
        // When / Then
        static::assertEquals(SignOnRequests::request(), $this->singleSignOn()->receivePost($this->tenant, ['SAMLRequest' => 'x']));
    }

    /**
     * Section 6.4 step 1: the request the receiver accepted over HTTP-Redirect, its service provider declared.
     */
    #[Test]
    public function aRequestRedirectedIsReceived(): void
    {
        // When / Then
        static::assertEquals(SignOnRequests::request(), $this->singleSignOn()->receiveRedirect($this->tenant, 'SAMLRequest=x'));
    }

    /**
     * Section 6.4 step 2: the declaration is read again when the request is posted too.
     */
    #[Test]
    public function aRequestPostedForAServiceProviderThatAsksForEncryptionIsRefused(): void
    {
        // Then
        $this->expectException(SignOnRefusedException::class);

        // When
        $this->singleSignOn(SignOnRequests::request(serviceProvider: self::ENCRYPTING))->receivePost($this->tenant, ['SAMLRequest' => 'x']);
    }

    private function singleSignOn(?SignOnRequest $received = null): SingleSignOn
    {
        return new SingleSignOn(
            new GivenRequests($received ?? SignOnRequests::request()),
            $this->responder,
            new ConfigurationServiceProviders(
                'acme',
                [
                    ServiceProviderDocuments::SIGNED => [
                        'metadata' => '/etc/saml/sp.xml',
                        'attributes' => [
                            'urn:oid:0.9.2342.19200300.100.1.3' => [
                                'claim' => 'email',
                                'friendly_name' => 'mail',
                            ],
                        ],
                    ],
                    self::ENCRYPTING => [
                        'metadata' => '/etc/saml/encrypting.xml',
                        'encrypt_assertions' => true,
                    ],
                ],
                new FixedClaims(),
            ),
            new AttributeRelease(new FixedClaims(['email' => 'alice@example.com']), new RecordingLogger()),
            new FixedSalt(),
            new FixedEndpoints(),
            $this->clock,
        );
    }

    /**
     * An active session of the tenant, its one proof a password at the instant given, the instant of the fixtures
     * by default.
     */
    private function session(?DateTimeImmutable $provenAt = null): AuthenticationSession
    {
        $provenAt ??= Fixtures::now();

        return Fixtures::session(
            Fixtures::user($this->tenant),
            $provenAt,
            AuthenticationProofs::of(AuthenticationMethod::password(), $provenAt),
        );
    }
}
