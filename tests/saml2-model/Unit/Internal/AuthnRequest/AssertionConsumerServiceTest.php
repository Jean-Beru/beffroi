<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\AuthnRequest\AssertionConsumerService;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\SamlLoader;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 6.2 step 4, M-9, SAML Metadata §2.2.3, SAML Core §3.4.1, section 8
 */
final class AssertionConsumerServiceTest extends TestCase
{
    private const string POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

    private const string REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    private const string ACS = 'https://sp.example.com/saml/acs';

    /**
     * M-9
     */
    #[Test]
    #[DataProvider('provideUrls')]
    public function itResolvesTheServiceOfTheUrl(string $attributes, ?string $binding): void
    {
        // Given
        $request = $this->request($attributes);
        $services = $this->services();

        // When
        $read = AssertionConsumerService::read($request, $services);

        // Then
        static::assertSame([$services->endpoints[1], self::ACS . '/second', null, $binding], $read);
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideUrls(): iterable
    {
        yield 'the URL alone' => [sprintf('AssertionConsumerServiceURL="%s/second"', self::ACS), null];
        yield 'the URL and HTTP-POST' => [
            sprintf('AssertionConsumerServiceURL="%s/second" ProtocolBinding="%s"', self::ACS, self::POST),
            self::POST,
        ];
    }

    /**
     * M-9
     */
    #[Test]
    #[DataProvider('provideIndexes')]
    public function itResolvesTheServiceOfTheIndex(string $index, int $position): void
    {
        // Given
        $request = $this->request(sprintf('AssertionConsumerServiceIndex="%s"', $index));
        $services = $this->services();

        // When
        $read = AssertionConsumerService::read($request, $services);

        // Then
        static::assertSame([$services->endpoints[$position], null, (int) $index, null], $read);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideIndexes(): iterable
    {
        yield 'zero' => ['0', 0];
        yield 'one' => ['1', 1];
        yield 'the largest' => ['65535', 2];
    }

    /**
     * §9.3 row 13, M-9, SAML Metadata §2.2.3
     */
    #[Test]
    #[DataProvider('provideNoService')]
    public function itResolvesTheDefaultServiceWhenTheRequestNamesNone(string $attributes, ?string $binding): void
    {
        // Given
        $request = $this->request($attributes);
        $services = $this->services();

        // When
        $read = AssertionConsumerService::read($request, $services);

        // Then
        static::assertSame([$services->endpoints[1], null, null, $binding], $read);
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function provideNoService(): iterable
    {
        yield 'nothing' => ['', null];
        yield 'HTTP-POST alone' => [sprintf('ProtocolBinding="%s"', self::POST), self::POST];
    }

    /**
     * §9.2 row 30, M-9
     */
    #[Test]
    #[DataProvider('provideServicesNotListed')]
    public function itRefusesAServiceTheMetadataDoesNotList(string $attributes, string $message): void
    {
        // Given
        $request = $this->request($attributes);

        // Then
        $this->expectException(UnknownEndpoint::class);
        $this->expectExceptionMessageIs($message);

        // When
        AssertionConsumerService::read($request, $this->services());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideServicesNotListed(): iterable
    {
        yield 'a URL' => [
            'AssertionConsumerServiceURL="https://attacker.example.com/acs"',
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'a URL with a trailing slash' => [
            sprintf('AssertionConsumerServiceURL="%s/"', self::ACS),
            'No assertion consumer service of the metadata has that location (M-9).',
        ];
        yield 'an index' => [
            'AssertionConsumerServiceIndex="3"',
            'No assertion consumer service of the metadata has that index (M-9).',
        ];
    }

    /**
     * §9.2 row 30, M-9, SAML Core §3.4.1
     */
    #[Test]
    #[DataProvider('provideIndexNextToAnother')]
    public function itRefusesAnIndexNextToAUrlOrABinding(string $attributes): void
    {
        // Given
        $request = $this->request($attributes);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('An AuthnRequest carries an AssertionConsumerServiceIndex next to an AssertionConsumerServiceURL or a ProtocolBinding, which SAML Core §3.4.1 makes mutually exclusive (M-9).');

        // When
        AssertionConsumerService::read($request, $this->services());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIndexNextToAnother(): iterable
    {
        yield 'next to a URL the metadata lists' => [
            sprintf('AssertionConsumerServiceURL="%s" AssertionConsumerServiceIndex="0"', self::ACS),
        ];
        yield 'next to a URL it does not list' => [
            'AssertionConsumerServiceURL="https://attacker.example.com/acs" AssertionConsumerServiceIndex="0"',
        ];
        yield 'next to HTTP-POST' => [sprintf('AssertionConsumerServiceIndex="0" ProtocolBinding="%s"', self::POST)];
    }

    /**
     * §9.2 row 33, section 8
     */
    #[Test]
    #[DataProvider('provideBindingsOtherThanPost')]
    public function itRefusesAProtocolBindingOtherThanPost(string $binding): void
    {
        // Given
        $request = $this->request(sprintf(
            'AssertionConsumerServiceURL="%s" ProtocolBinding="%s"',
            self::ACS,
            $binding,
        ));

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');

        // When
        AssertionConsumerService::read($request, $this->services());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBindingsOtherThanPost(): iterable
    {
        yield 'HTTP-Redirect' => [self::REDIRECT];
        yield 'HTTP-Artifact' => ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'];
    }

    /**
     * Section 8
     */
    #[Test]
    public function itAcceptsThePostProtocolBindingOnly(): void
    {
        // When / Then
        static::assertSame(self::POST, AssertionConsumerService::protocolBinding(self::POST));
    }

    /**
     * M-6
     */
    #[Test]
    #[DataProvider('provideMalformedAttributes')]
    public function itRefusesAnAttributeNotOfItsLexicalForm(string $attributes, string $message): void
    {
        // Given
        $request = $this->request($attributes);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        AssertionConsumerService::read($request, $this->services());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideMalformedAttributes(): iterable
    {
        $index = 'An index is not an xs:unsignedShort, digits without sign or leading zero from 0 to 65535 (M-6).';
        yield 'an index with a leading zero' => ['AssertionConsumerServiceIndex="01"', $index];
        yield 'an index with a sign' => ['AssertionConsumerServiceIndex="+1"', $index];
        yield 'a negative index' => ['AssertionConsumerServiceIndex="-1"', $index];
        yield 'an index surrounded by whitespace' => ['AssertionConsumerServiceIndex=" 1"', $index];
        yield 'an index followed by a line feed' => ['AssertionConsumerServiceIndex="1&#10;"', $index];
        yield 'an index of six digits' => ['AssertionConsumerServiceIndex="100000"', $index];
        yield 'an index over 65535' => ['AssertionConsumerServiceIndex="65536"', $index];
        yield 'an empty index' => ['AssertionConsumerServiceIndex=""', $index];
        yield 'a relative URL' => ['AssertionConsumerServiceURL="/saml/acs"', 'A URI is not absolute (M-6).'];
        yield 'a relative ProtocolBinding' => ['ProtocolBinding="HTTP-POST"', 'A URI is not absolute (M-6).'];
    }

    private function services(): IndexedEndpoints
    {
        return new IndexedEndpoints([
            new IndexedEndpoint(Binding::HttpPost, self::ACS, 0),
            new IndexedEndpoint(Binding::HttpPost, self::ACS . '/second', 1, true),
            new IndexedEndpoint(Binding::HttpPost, self::ACS . '/third', 65_535),
        ]);
    }

    private function request(string $attributes): Element
    {
        return SamlLoader::create()
            ->load(sprintf(
                '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" %s/>',
                $attributes,
            ))
            ->root();
    }
}
