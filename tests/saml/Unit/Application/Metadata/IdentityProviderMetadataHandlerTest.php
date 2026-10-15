<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\IdentityProviderMetadataHandler;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Model\ModelMetadataWriter;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Tests\Fixture\FixedEndpoints;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md section 6.1, S-2, S-4: the metadata of the identity provider of a tenant, written by saml2-model's
 * MetadataWriter and read back by its MetadataReader.
 */
final class IdentityProviderMetadataHandlerTest extends TestCase
{
    private const string ISSUER = 'https://id.acme.example';

    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', self::ISSUER);
        $this->keys = new InMemoryTenantKeyRepository();
    }

    /**
     * Section 6.1 steps 3 to 5, S-4: the entity ID is the URL of the metadata, each service is listed with
     * HTTP-Redirect then HTTP-POST at its URL under the issuer, the certificate of the key is a signing one, and
     * WantAuthnRequestsSigned is true when the tenant says nothing.
     */
    #[Test]
    public function itIsReadBackByTheMetadataReaderOfTheModel(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);

        // When
        $metadata = $this->handler()->handle($this->tenant);

        // Then
        $entityId = self::ISSUER . FixedEndpoints::METADATA;
        static::assertEquals(new EntityDescriptor($entityId, null, new IdentityProvider(
            $entityId,
            [$this->certificateOf($key)],
            [],
            [
                new Endpoint(Binding::HttpRedirect, self::ISSUER . FixedEndpoints::SINGLE_SIGN_ON),
                new Endpoint(Binding::HttpPost, self::ISSUER . FixedEndpoints::SINGLE_SIGN_ON),
            ],
            [
                new Endpoint(Binding::HttpRedirect, self::ISSUER . FixedEndpoints::SINGLE_LOGOUT),
                new Endpoint(Binding::HttpPost, self::ISSUER . FixedEndpoints::SINGLE_LOGOUT),
            ],
            wantAuthnRequestsSigned: true,
        )), self::read($metadata->document));
    }

    /**
     * S-4, model.md section 6.9: a tenant that turns WantAuthnRequestsSigned off says so in its metadata.
     */
    #[Test]
    public function itSaysWhatTheTenantSetOfSignedRequests(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $metadata = $this->handler(wantAuthnRequestsSigned: false)->handle($this->tenant);

        // Then
        static::assertFalse(self::read($metadata->document)->identityProvider?->wantAuthnRequestsSigned);
    }

    /**
     * S-2: during a rotation, the certificate of the staged key is published beside the active one's before the
     * staged key signs anything.
     */
    #[Test]
    public function itPublishesTheNextCertificateBesideTheCurrentOne(): void
    {
        // Given
        $active = SamlKeys::activeKey($this->tenant);
        $staged = SamlKeys::key($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $this->keys->save($active);
        $this->keys->save($staged);

        // When
        $metadata = $this->handler()->handle($this->tenant);

        // Then
        static::assertSame(
            [$this->certificateOf($active), $this->certificateOf($staged)],
            self::read($metadata->document)->identityProvider?->signingCertificates,
        );
    }

    /**
     * Section 6.1 step 1: a tenant that holds no SAML key in service has no metadata.
     */
    #[Test]
    public function aTenantWithoutASamlKeyHasNoMetadata(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no SAML signing key: its identity provider has no metadata to publish (spec/saml.md section 6.1 step 1).');

        // When
        $this->handler()->handle($this->tenant);
    }

    /**
     * Section 6.1 step 6, S-2: the metadata may be cached for the max-age of the keys of the tenant and no longer.
     */
    #[Test]
    public function itIsCachedForTheMaxAgeOfTheKeys(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $metadata = $this->handler(maxAge: 120)->handle($this->tenant);

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'public, max-age=120',
            ],
            $metadata->headers,
        );
    }

    /**
     * Section 6.1 step 6: a lifetime that is not a number of seconds is refused when the handler is built, so that a
     * deployment learns it at boot.
     */
    #[Test]
    public function itRefusesALifetimeThatIsNotANumberOfSeconds(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The cache lifetime of the metadata is a number of seconds (spec/saml.md section 6.1 step 6).');

        // When
        $this->handler(maxAge: -1);
    }

    private function handler(
        bool $wantAuthnRequestsSigned = true,
        int $maxAge = IdentityProviderMetadataHandler::DEFAULT_MAX_AGE,
    ): IdentityProviderMetadataHandler {
        return new IdentityProviderMetadataHandler(
            new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer()),
            new FixedEndpoints(),
            new ModelMetadataWriter(),
            $wantAuthnRequestsSigned,
            $maxAge,
        );
    }

    private function certificateOf(TenantKey $key): string
    {
        return new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($key))->base64;
    }

    private static function read(string $document): EntityDescriptor
    {
        return new MetadataReader(SamlLoader::create(), new MockClock(Fixtures::now()))->readTrusted(SamlLoader::create()->load($document));
    }
}
