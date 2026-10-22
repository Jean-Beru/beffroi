<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Upstream\EmailDomain;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;

/**
 * spec/saml.md S-44: an e-mail domain an upstream identity provider answers for, a name of the DNS kept in lower case.
 */
final class EmailDomainTest extends TestCase
{
    /**
     * S-44, RFC 4343: a domain is read without regard to case and kept in lower case, so that two spellings are one.
     */
    #[Test]
    public function aDomainIsKeptInLowerCase(): void
    {
        // When / Then
        static::assertSame('acme.example', new EmailDomain('Acme.EXAMPLE')->value);
    }

    /**
     * S-44, RFC 1035 §2.3.4, RFC 1123 §2.1, RFC 5890 §2.3.2.1: a name of the DNS of two labels at least.
     */
    #[Test]
    #[DataProvider('provideDomains')]
    public function aNameOfTheDnsIsADomain(string $domain): void
    {
        // When / Then
        static::assertSame($domain, new EmailDomain($domain)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDomains(): iterable
    {
        yield 'two labels' => ['acme.example'];
        yield 'a subdomain' => ['eu.acme.example'];
        yield 'digits and hyphens' => ['a-1.2b.example'];
        yield 'an A-label' => ['xn--bcher-kva.example'];
        yield 'a label of 63 characters' => [str_repeat('a', 63) . '.example'];
        yield 'a name of 253 characters' => [self::longName(61)];
    }

    /**
     * S-44: what is no name of the DNS of two labels at least is refused.
     */
    #[Test]
    #[DataProvider('provideWhatIsNoDomain')]
    public function whatIsNoNameOfTheDnsIsRefused(string $domain): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf(
            '"%s" is no e-mail domain: a name of the DNS of two labels at least, of letters, digits and hyphens, a name outside ASCII written as its A-label (spec/saml.md S-44).',
            $domain,
        ));

        // When
        new EmailDomain($domain);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoDomain(): iterable
    {
        yield 'nothing' => [''];
        yield 'one label' => ['localhost'];
        yield 'an empty label' => ['acme..example'];
        yield 'a dot first' => ['.acme.example'];
        yield 'a dot last' => ['acme.example.'];
        yield 'a label of 64 characters' => [str_repeat('a', 64) . '.example'];
        yield 'a hyphen first in a label' => ['-acme.example'];
        yield 'a hyphen last in a label' => ['acme-.example'];
        yield 'an underscore' => ['ac_me.example'];
        yield 'a name outside ASCII' => ['bücher.example'];
        yield 'a name of 254 characters' => [self::longName(62)];
        yield 'an IPv4 address' => ['192.0.2.1'];
        yield 'an address' => ['alice@acme.example'];
        yield 'a port' => ['acme.example:443'];
        yield 'a space' => ['acme .example'];
        yield 'a line feed after it' => ["acme.example\n"];
    }

    /**
     * Three labels of 63 characters, then a last one of the length given.
     */
    private static function longName(int $last): string
    {
        return str_repeat('a', 63) . '.' . str_repeat('b', 63) . '.' . str_repeat('c', 63) . '.' . str_repeat('d', $last);
    }
}
