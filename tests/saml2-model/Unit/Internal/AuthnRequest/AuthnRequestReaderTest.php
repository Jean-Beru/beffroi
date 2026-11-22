<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Internal\AuthnRequest;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Internal\AuthnRequest\AuthnRequestReader;
use Beffroi\Saml2\Model\SamlLoader;
use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 6.2 step 1, M-4, M-5, SAML Core §3.2.1, §3.4.1
 */
final class AuthnRequestReaderTest extends TestCase
{
    private const string ISSUER = '<saml:Issuer>https://sp.example.com/saml</saml:Issuer>';

    private const string SIGNATURE = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>';

    private const string EXTENSIONS = '<samlp:Extensions/>';

    private const string POLICY = '<samlp:NameIDPolicy/>';

    private const string CONTEXT = '<samlp:RequestedAuthnContext/>';

    /**
     * M-5
     */
    #[Test]
    #[DataProvider('provideSequences')]
    public function itAcceptsTheChildrenInTheOrderOfTheSchema(string $children): void
    {
        // Given
        $request = $this->request($children);

        // Then
        $this->expectNotToPerformAssertions();

        // When
        AuthnRequestReader::structure($request);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSequences(): iterable
    {
        yield 'every child' => [self::ISSUER . self::SIGNATURE . self::EXTENSIONS . self::POLICY . self::CONTEXT];
        yield 'the saml:Issuer alone' => [self::ISSUER];
        yield 'the saml:Issuer and the samlp:RequestedAuthnContext' => [self::ISSUER . self::CONTEXT];
    }

    /**
     * M-5
     */
    #[Test]
    #[DataProvider('provideChildrenOutOfOrder')]
    public function itRefusesAChildOutOfOrder(string $children): void
    {
        // Given
        $request = $this->request($children);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:AuthnRequest holds a child out of the order of the schema, or one it does not allow there (M-5).');

        // When
        AuthnRequestReader::structure($request);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideChildrenOutOfOrder(): iterable
    {
        yield 'the saml:Issuer after the samlp:Extensions' => [self::EXTENSIONS . self::ISSUER];
        yield 'the samlp:RequestedAuthnContext before the samlp:NameIDPolicy' => [
            self::ISSUER . self::CONTEXT . self::POLICY,
        ];
        yield 'a samlp:Extensions after the samlp:RequestedAuthnContext' => [
            self::ISSUER . self::CONTEXT . self::EXTENSIONS,
        ];
    }

    /**
     * M-4
     */
    #[Test]
    #[DataProvider('provideRepeatedChildren')]
    public function itRefusesARepeatedChild(string $children, string $label): void
    {
        // Given
        $request = $this->request($children);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs(sprintf('The samlp:AuthnRequest holds more than one %s (M-4).', $label));

        // When
        AuthnRequestReader::structure($request);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRepeatedChildren(): iterable
    {
        yield 'two saml:Issuer' => [self::ISSUER . self::ISSUER, 'saml:Issuer'];
        yield 'two samlp:Extensions' => [self::ISSUER . self::EXTENSIONS . self::EXTENSIONS, 'samlp:Extensions'];
        yield 'two samlp:RequestedAuthnContext' => [
            self::ISSUER . self::CONTEXT . self::CONTEXT,
            'samlp:RequestedAuthnContext',
        ];
    }

    /**
     * M-4, Profiles §4.1.4.1
     */
    #[Test]
    public function itRefusesARequestWithoutIssuer(): void
    {
        // Given
        $request = $this->request(self::EXTENSIONS . self::POLICY);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:AuthnRequest holds no saml:Issuer (M-4).');

        // When
        AuthnRequestReader::structure($request);
    }

    private function request(string $children): Element
    {
        return SamlLoader::create()
            ->load(sprintf(
                '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</samlp:AuthnRequest>',
                $children,
            ))
            ->root();
    }
}
