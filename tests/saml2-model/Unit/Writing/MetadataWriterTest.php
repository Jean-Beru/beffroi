<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Writing;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Core\Text;
use DateTimeImmutable;
use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function array_map;
use function preg_match;

/**
 * Sections 5.7, 6.6 and 9.1, M-15
 */
final class MetadataWriterTest extends TestCase
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * Section 9.1, M-15
     */
    #[Test]
    #[DataProvider('provideDescriptors')]
    public function itWritesWhatItsReaderReads(EntityDescriptor $descriptor): void
    {
        // Given
        $document = new MetadataWriter()->write($descriptor, null);

        // When
        $read = $this->reader()->readTrusted($this->reload($document));

        // Then
        static::assertEquals($descriptor, $read);
    }

    /**
     * @return iterable<string, array{EntityDescriptor}>
     */
    public static function provideDescriptors(): iterable
    {
        yield 'an identity provider' => [new EntityDescriptor(
            'https://idp.example.com/saml',
            new DateTimeImmutable('2026-10-30T12:00:00Z'),
            self::identityProvider('https://idp.example.com/saml'),
        )];
        yield 'a service provider' => [new EntityDescriptor(
            'https://sp.example.com/saml',
            null,
            null,
            self::serviceProvider('https://sp.example.com/saml'),
        )];
        yield 'an entity in both roles' => [new EntityDescriptor(
            'https://entity.example.com/saml',
            null,
            self::identityProvider('https://entity.example.com/saml'),
            self::serviceProvider('https://entity.example.com/saml'),
        )];
        yield 'the least each role holds' => [new EntityDescriptor(
            'https://entity.example.com/saml',
            null,
            new IdentityProvider(
                'https://entity.example.com/saml',
                [],
                [],
                [
                    new Endpoint(Binding::HttpPost, 'https://entity.example.com/saml/sso'),
                ],
            ),
            new ServiceProvider('https://entity.example.com/saml', [], [], new IndexedEndpoints([
                new IndexedEndpoint(Binding::HttpPost, 'https://entity.example.com/saml/acs', 0),
            ])),
        )];
    }

    /**
     * Section 9.1, M-2, M-15
     */
    #[Test]
    #[DataProvider('provideSignedDescriptors')]
    public function itSignsWhatItsReaderVerifies(EntityDescriptor $descriptor, string $key): void
    {
        // Given
        $key = $key === 'sp' ? 'sp' : 'idp';
        $document = new MetadataWriter()->write($descriptor, new Signing(MetadataFixtures::signingKey($key)));

        // When
        $read = $this->reader()->readSigned($this->reload($document), MetadataFixtures::verificationKeys($key));

        // Then
        static::assertEquals($descriptor, $read);
    }

    /**
     * @return iterable<string, array{EntityDescriptor, string}>
     */
    public static function provideSignedDescriptors(): iterable
    {
        yield 'an identity provider' => [
            new EntityDescriptor(
                'https://idp.example.com/saml',
                null,
                self::identityProvider('https://idp.example.com/saml'),
            ),
            'idp',
        ];
        yield 'a service provider' => [
            new EntityDescriptor(
                'https://sp.example.com/saml',
                null,
                null,
                self::serviceProvider('https://sp.example.com/saml'),
            ),
            'sp',
        ];
    }

    /**
     * Section 9.1
     */
    #[Test]
    public function itReadsTheSignedMetadataXmlsec1Verified(): void
    {
        // Given
        $document = MetadataFixtures::load('behaviour/metadata-written-and-signed-by-the-writer.xml');

        // When
        $descriptor = self::reader()->readSigned($document, MetadataFixtures::verificationKeys('idp'));

        // Then
        static::assertSame(
            [
                'https://entity.example.com/saml',
                '2026-10-30T12:00:00Z',
                [MetadataFixtures::certificate('idp')],
                [MetadataFixtures::certificate('sp')],
            ],
            [
                $descriptor->entityId,
                $descriptor->validUntil?->format('Y-m-d\TH:i:s\Z'),
                $descriptor->identityProvider?->signingCertificates,
                $descriptor->serviceProvider?->signingCertificates,
            ],
        );
    }

    /**
     * Section 6.6 step 3, SAML Core §5.4.1, dsig.md section 6.2
     */
    #[Test]
    public function itSignsTheRootWithTheSignatureFirst(): void
    {
        // Given
        $signing = new Signing(
            MetadataFixtures::signingKey('idp'),
            certificatePem: MetadataFixtures::certificatePem('idp'),
        );

        // When
        $root = new MetadataWriter()
            ->write($this->identityProviderDescriptor(), $signing)
            ->root();

        // Then
        $signature = Children::all($root)[0];
        $signedInfo = Children::one($signature, new Name(self::DSIG, 'SignedInfo'));
        static::assertSame(
            [
                'Signature',
                '#' . Attributes::required($root, new Name(null, 'ID')),
                [],
                MetadataFixtures::certificate('idp'),
            ],
            [
                $signature->localName,
                Attributes::required(
                    Children::one($signedInfo, new Name(self::DSIG, 'Reference')),
                    new Name(null, 'URI'),
                ),
                $this->descendantsNamed($signature, 'InclusiveNamespaces'),
                Text::of($this->path($signature, ['KeyInfo', 'X509Data', 'X509Certificate'])),
            ],
        );
    }

    /**
     * Section 6.6 step 2, M-15, SAML Core §1.3.4
     */
    #[Test]
    public function itDrawsANewIdAtEveryWrite(): void
    {
        // Given
        $writer = new MetadataWriter();

        // When
        $first = Attributes::required(
            $writer->write($this->identityProviderDescriptor(), null)->root(),
            new Name(null, 'ID'),
        );
        $second = Attributes::required(
            $writer->write($this->identityProviderDescriptor(), null)->root(),
            new Name(null, 'ID'),
        );

        // Then
        static::assertSame([1, 1, false], [
            preg_match('~^_[0-9a-f]{40}\z~', $first),
            preg_match('~^_[0-9a-f]{40}\z~', $second),
            $first === $second,
        ]);
    }

    /**
     * Section 6.6 step 2, core.md section 6.5
     */
    #[Test]
    public function itWritesOnePrefixPerNamespace(): void
    {
        // Given
        $descriptor = new EntityDescriptor(
            'https://entity.example.com/saml',
            null,
            self::identityProvider('https://entity.example.com/saml'),
            self::serviceProvider('https://entity.example.com/saml'),
        );

        // When
        $document = new MetadataWriter()->write($descriptor, null);

        // Then
        static::assertSame(
            [['md', 'urn:oasis:names:tc:SAML:2.0:metadata'], ['ds', self::DSIG]],
            array_values(array_unique(
                array_map(
                    static fn (Element $element): array => [$element->prefix, $element->namespaceURI],
                    self::elements($document->root()),
                ),
                SORT_REGULAR,
            )),
        );
    }

    /**
     * Section 6.6 step 2, SAML Metadata §2.3.2
     */
    #[Test]
    public function itWritesTheCacheDurationAsADurationInSeconds(): void
    {
        // Given
        $descriptor = new EntityDescriptor(
            'https://idp.example.com/saml',
            null,
            self::identityProvider('https://idp.example.com/saml'),
            cacheDuration: 86_400,
        );

        // When
        $document = new MetadataWriter()->write($descriptor, null);

        // Then
        static::assertSame('PT86400S', Attributes::optional($this->reload($document)->root(), new Name(null, 'cacheDuration')));
    }

    /**
     * Section 6.6 step 2
     */
    #[Test]
    public function itWritesNoCacheDurationWhenNoneIsGiven(): void
    {
        // When
        $document = new MetadataWriter()->write($this->identityProviderDescriptor(), null);

        // Then
        static::assertNull(Attributes::optional($document->root(), new Name(null, 'cacheDuration')));
    }

    /**
     * Section 6.5 step 3, M-15
     */
    #[Test]
    public function itsReaderReadsTheMetadataAndNotItsCacheDuration(): void
    {
        // Given
        $document = new MetadataWriter()->write(new EntityDescriptor(
            'https://idp.example.com/saml',
            null,
            self::identityProvider('https://idp.example.com/saml'),
            cacheDuration: 86_400,
        ), null);

        // When
        $read = $this->reader()->readTrusted($this->reload($document));

        // Then
        static::assertSame(['https://idp.example.com/saml', null], [$read->entityId, $read->cacheDuration]);
    }

    /**
     * Section 5.7
     */
    #[Test]
    public function itWritesNoSignatureWithoutSigning(): void
    {
        // When
        $document = new MetadataWriter()->write($this->identityProviderDescriptor(), null);

        // Then
        static::assertSame([], $this->descendantsNamed($document->root(), 'Signature'));
    }

    /**
     * Section 6.6 step 1, section 5.8, M-15
     */
    #[Test]
    #[DataProvider('provideDescriptorsRefused')]
    public function itRefusesWhatItsReaderRefuses(EntityDescriptor $descriptor, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        new MetadataWriter()->write($descriptor, null);
    }

    /**
     * @return iterable<string, array{EntityDescriptor, string}>
     */
    public static function provideDescriptorsRefused(): iterable
    {
        $entityId = 'https://entity.example.com/saml';
        yield 'no role' => [
            new EntityDescriptor($entityId),
            'The entity descriptor holds no role to write (section 6.6).',
        ];
        yield 'an identity provider without single sign-on service' => [
            new EntityDescriptor($entityId, null, new IdentityProvider($entityId, [], [], [])),
            'The identity provider holds no single sign-on service, which its reader requires (section 6.6).',
        ];
        yield 'a service provider without assertion consumer service' => [
            new EntityDescriptor(
                $entityId,
                null,
                null,
                new ServiceProvider($entityId, [], [], new IndexedEndpoints([])),
            ),
            'The service provider holds no assertion consumer service, which its reader requires (section 6.6).',
        ];
    }

    private static function identityProvider(string $entityId): IdentityProvider
    {
        return new IdentityProvider(
            $entityId,
            [MetadataFixtures::certificate('idp'), MetadataFixtures::certificate('sp')],
            [MetadataFixtures::certificate('idp')],
            [
                new Endpoint(Binding::HttpRedirect, $entityId . '/sso'),
                new Endpoint(Binding::HttpPost, $entityId . '/sso'),
            ],
            [new Endpoint(Binding::HttpRedirect, $entityId . '/slo', $entityId . '/slo/response')],
            [NameIdFormat::Persistent, NameIdFormat::Transient],
            true,
        );
    }

    private static function serviceProvider(string $entityId): ServiceProvider
    {
        return new ServiceProvider(
            $entityId,
            [MetadataFixtures::certificate('sp')],
            [MetadataFixtures::certificate('sp')],
            new IndexedEndpoints([
                new IndexedEndpoint(Binding::HttpPost, $entityId . '/acs', 3, false),
                new IndexedEndpoint(Binding::HttpPost, $entityId . '/acs/other', 1, true),
                new IndexedEndpoint(Binding::HttpPost, $entityId . '/acs/third', 0),
            ]),
            [new Endpoint(Binding::HttpPost, $entityId . '/slo')],
            [NameIdFormat::EmailAddress],
            true,
            true,
        );
    }

    private function identityProviderDescriptor(): EntityDescriptor
    {
        return new EntityDescriptor(
            'https://idp.example.com/saml',
            null,
            self::identityProvider('https://idp.example.com/saml'),
        );
    }

    private function reader(): MetadataReader
    {
        return new MetadataReader(SamlLoader::create(), new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')));
    }

    /**
     * Section 9.1
     */
    private function reload(Document $document): Document
    {
        return SamlLoader::create()->load(new Serializer()->serialize($document));
    }

    /**
     * @return list<Element> $element and every element under it, in document order
     */
    private static function elements(Element $element): array
    {
        $elements = [$element];
        foreach (Children::all($element) as $child) {
            $elements = [...$elements, ...self::elements($child)];
        }

        return $elements;
    }

    /**
     * @return list<Element>
     */
    private function descendantsNamed(Element $element, string $local): array
    {
        return array_values(array_filter(
            self::elements($element),
            static fn (Element $candidate): bool => $candidate->namespaceURI === self::DSIG && $candidate->localName === $local,
        ));
    }

    /**
     * @param list<string> $locals
     */
    private function path(Element $element, array $locals): Element
    {
        foreach ($locals as $local) {
            $element = Children::one($element, new Name(self::DSIG, $local));
        }

        return $element;
    }
}
