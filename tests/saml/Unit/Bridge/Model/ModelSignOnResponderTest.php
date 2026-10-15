<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Bridge\Model\ModelSignOnResponder;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\PersistentNameId;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Domain\SingleSignOn\SignOnFailure;
use Beffroi\Saml\Domain\SingleSignOn\SignOnResponse;
use Beffroi\Saml\Domain\SingleSignOn\SignOnStatus;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignOnRequests;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat as ModelAttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 6.4 step 7, S-13 to S-16: the answer written with the model's objects, signed by the SAML key of
 * the tenant and turned into the form of HTTP-POST, read back as the service provider reads it, by PostReceiver and
 * saml2-model's ResponseValidator under the certificate the metadata publish.
 */
final class ModelSignOnResponderTest extends TestCase
{
    private const string IDENTITY_PROVIDER = 'https://id.acme.example/saml/metadata';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private TenantKey $key;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($this->key);
    }

    /**
     * S-15, section 6.4 step 7: the form posts to the endpoint the model resolved, the RelayState received given
     * back as it was.
     */
    #[Test]
    public function theFormPostsToTheEndpointWithTheRelayStateReceived(): void
    {
        // When
        $form = $this->responder()->success($this->tenant, self::response());

        // Then
        static::assertSame(
            [SignOnRequests::ASSERTION_CONSUMER, 'state-1'],
            [$form->action, $form->fields['RelayState'] ?? null],
        );
    }

    /**
     * S-15: the response and its assertion are both signed by the SAML key of the tenant, which the service
     * provider verifies under the certificate of the metadata.
     */
    #[Test]
    public function theResponseAndItsAssertionAreSigned(): void
    {
        // When
        $accepted = $this->accepted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertSame(SignatureCoverage::AssertionAndResponse, $accepted->coverage);
    }

    /**
     * S-13: the persistent identifier, qualified by the identity provider and the service provider.
     */
    #[Test]
    public function theSubjectIsThePersistentIdentifierQualifiedByBothEntities(): void
    {
        // When
        $accepted = $this->accepted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertEquals(
            new NameId('alice-at-sp', NameIdFormat::Persistent, self::IDENTITY_PROVIDER, ServiceProviderDocuments::SIGNED),
            $accepted->assertion->nameId,
        );
    }

    /**
     * S-14: the assertion is addressed to the request that asked for it: its issuer, its audience, its recipient and
     * the request it answers.
     */
    #[Test]
    public function theAssertionIsAddressedToTheRequest(): void
    {
        // When
        $assertion = $this->accepted($this->responder()->success($this->tenant, self::response()))->assertion;

        // Then
        static::assertSame(
            [self::IDENTITY_PROVIDER, [[ServiceProviderDocuments::SIGNED]], SignOnRequests::ASSERTION_CONSUMER, SignOnRequests::ID],
            [$assertion->issuer->entityId, $assertion->conditions->audiences, $assertion->confirmation->recipient, $assertion->confirmation->inResponseTo],
        );
    }

    /**
     * S-15: valid five minutes from its issue, without NotBefore.
     */
    #[Test]
    public function theAssertionIsValidFiveMinutes(): void
    {
        // When
        $assertion = $this->accepted($this->responder()->success($this->tenant, self::response()))->assertion;

        // Then
        static::assertSame(
            [null, '2026-09-15T10:05:00+00:00', '2026-09-15T10:05:00+00:00', '2026-09-15T10:00:00+00:00'],
            [
                $assertion->conditions->notBefore,
                $assertion->conditions->notOnOrAfter?->format('c'),
                $assertion->confirmation->notOnOrAfter->format('c'),
                $assertion->issueInstant->format('c'),
            ],
        );
    }

    /**
     * Section 6.4 step 7: the session by its ID and its latest proof, and the unspecified class.
     */
    #[Test]
    public function theStatementIsOfTheSession(): void
    {
        // When
        $statement = $this->accepted($this->responder()->success($this->tenant, self::response()))->assertion->authnStatement;

        // Then
        static::assertSame(
            ['the-session', '2026-09-15T09:30:00+00:00', 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified', null],
            [$statement->sessionIndex, $statement->authnInstant->format('c'), $statement->authnContextClassRef, $statement->sessionNotOnOrAfter],
        );
    }

    /**
     * S-16: the attributes released, under their mapping, without xsi:type.
     */
    #[Test]
    public function theAttributesAreTheOnesReleased(): void
    {
        // When
        $accepted = $this->accepted($this->responder()->success($this->tenant, self::response()));

        // Then
        static::assertEquals(
            [new Attribute('urn:oid:0.9.2342.19200300.100.1.3', ModelAttributeNameFormat::Uri, 'mail', ['alice@example.com', 'alice@example.org'])],
            $accepted->assertion->attributes,
        );
    }

    /**
     * Section 6.4 steps 4 and 7: a failure carries its status and no assertion, to the same endpoint.
     */
    #[Test]
    public function aFailureCarriesItsStatus(): void
    {
        // Given
        $form = $this->responder()->failure($this->tenant, new SignOnFailure(self::IDENTITY_PROVIDER, SignOnRequests::request(), SignOnStatus::NoPassive, Fixtures::now()));

        // When
        try {
            $this->accepted($form);
            static::fail('A failure carries no assertion.');
        } catch (UnsuccessfulResponse $failure) {
            // Then
            static::assertSame(
                [StatusCode::Responder, SecondLevelStatusCode::NoPassive],
                [$failure->status->code, $failure->status->secondLevel],
            );
        }
    }

    /**
     * Section 6.4 step 7: a failure goes back with the RelayState received too.
     */
    #[Test]
    public function aFailureGivesTheRelayStateBack(): void
    {
        // When
        $form = $this->responder()->failure($this->tenant, new SignOnFailure(self::IDENTITY_PROVIDER, SignOnRequests::request(), SignOnStatus::InvalidNameIdPolicy, Fixtures::now()));

        // Then
        static::assertSame([SignOnRequests::ASSERTION_CONSUMER, 'state-1'], [$form->action, $form->fields['RelayState'] ?? null]);
    }

    /**
     * S-1: a tenant that holds no active SAML key signs nothing.
     */
    #[Test]
    public function aTenantWithoutAnActiveKeySignsNothing(): void
    {
        // Given
        $this->keys = new InMemoryTenantKeyRepository();

        // Then
        $this->expectException(KeyNotFoundException::class);

        // When
        $this->responder()->success($this->tenant, self::response());
    }

    private function responder(): ModelSignOnResponder
    {
        return new ModelSignOnResponder(new SealedKeyProvider($this->keys, Keys::opened()), SamlKeys::algorithm());
    }

    private function accepted(PostedForm $form): AcceptedAssertion
    {
        $certificate = new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key));

        return new PostReceiver(SamlLoader::create())->response($form->fields)->validate(
            new ResponseValidator(SamlLoader::create(), new FrozenClock(Fixtures::now()), new InMemoryReplayGuard()),
            new IdentityProvider(self::IDENTITY_PROVIDER, [$certificate->base64], [], [
                new Endpoint(Binding::HttpRedirect, 'https://id.acme.example/saml/sso'),
            ]),
            ExpectedResponse::toRequest(SignOnRequests::ID, SignOnRequests::ASSERTION_CONSUMER, ServiceProviderDocuments::SIGNED),
        );
    }

    private static function response(): SignOnResponse
    {
        return new SignOnResponse(
            self::IDENTITY_PROVIDER,
            SignOnRequests::request(),
            new PersistentNameId('alice-at-sp'),
            [new ReleasedAttribute('urn:oid:0.9.2342.19200300.100.1.3', AttributeNameFormat::Uri, 'mail', array_map(
                static fn (string $value): AttributeValue => new AttributeValue($value),
                ['alice@example.com', 'alice@example.org'],
            ))],
            'the-session',
            Fixtures::now()->modify('-30 minutes'),
            Fixtures::now(),
        );
    }
}
