<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\LogoutFixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_replace;

/**
 * Section 5.4, M-1
 */
final class UnverifiedLogoutRequestTest extends TestCase
{
    private const string REQUEST = 'behaviour/logout-request-written-for-http-redirect.xml';

    /**
     * Section 5.4
     */
    #[Test]
    public function itReadsTheIssuer(): void
    {
        // Given
        $document = MetadataFixtures::load(self::REQUEST);

        // When
        $request = UnverifiedLogoutRequest::of($document);

        // Then
        static::assertSame([LogoutFixtures::IDP, $document], [$request->issuer, $request->document]);
    }

    /**
     * Section 5.4, SAML Core §3.2.1, SAML Profiles §4.4.4.1
     */
    #[Test]
    public function itReadsNoIssuerAsNull(): void
    {
        // When
        $request = UnverifiedLogoutRequest::of(MetadataFixtures::load('hostile/logout-request-without-issuer-refused.xml'));

        // Then
        static::assertNull($request->issuer);
    }

    /**
     * Section 5.4
     */
    #[Test]
    #[DataProvider('provideOtherRoots')]
    public function itRefusesAnotherRoot(string $path): void
    {
        // Given
        $document = MetadataFixtures::load($path);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The root of the message is not a samlp:LogoutRequest (section 5.4).');

        // When
        UnverifiedLogoutRequest::of($document);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherRoots(): iterable
    {
        yield 'a samlp:LogoutResponse' => ['behaviour/logout-response-written-for-http-redirect.xml'];
        yield 'an md:EntityDescriptor' => ['behaviour/metadata-identity-provider.xml'];
    }

    /**
     * Section 5.4, M-4
     */
    #[Test]
    public function itRefusesTwoIssuers(): void
    {
        // Given
        $document = MetadataFixtures::load('hostile/logout-request-two-issuers-refused.xml');

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('The samlp:LogoutRequest holds more than one saml:Issuer (M-4).');

        // When
        UnverifiedLogoutRequest::of($document);
    }

    /**
     * Section 5.4, M-6, M-16
     */
    #[Test]
    public function itRefusesAnIssuerThatIsNotAUri(): void
    {
        // Given
        $document = SamlLoader::create()->load(str_replace(
            '>' . LogoutFixtures::IDP . '<',
            '>idp.example.com<',
            MetadataFixtures::bytes(self::REQUEST),
        ));

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        UnverifiedLogoutRequest::of($document);
    }
}
