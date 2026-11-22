<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function array_filter;
use function array_map;
use function array_values;
use function base64_encode;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function explode;
use function gzdeflate;
use function implode;
use function is_string;
use LogicException;
use function preg_replace_callback;
use function rawurlencode;
use function sprintf;
use function strtolower;
use const ZLIB_ENCODING_RAW;

/**
 * Sections 9.2 and 9.3, B-2, SAML Bindings §3.4.4.1
 */
final readonly class RedirectQuery
{
    /**
     * @param list<array{string, string}> $parameters each name and value as on the wire, in order
     */
    private function __construct(
        private array $parameters,
    ) {
    }

    public static function none(): self
    {
        return new self([]);
    }

    /**
     * Section 6.1 step 2
     */
    public static function of(string $queryString): self
    {
        return new self(array_map(
            static function (string $segment): array {
                $pair = explode('=', $segment, 2);

                return [$pair[0], $pair[1] ?? ''];
            },
            explode('&', $queryString),
        ));
    }

    /**
     * SAML Bindings §3.4.4.1
     */
    public static function carrying(string $name, string $xml): self
    {
        return new self([[$name, self::message($xml)]]);
    }

    /**
     * RFC 1951
     */
    public static function message(string $xml): string
    {
        $deflated = gzdeflate($xml, -1, ZLIB_ENCODING_RAW);
        if (! is_string($deflated)) {
            throw new LogicException('zlib could not deflate a message of the tests.');
        }

        return self::encode(base64_encode($deflated));
    }

    /**
     * RFC 3986
     */
    public static function encode(string $bytes): string
    {
        return rawurlencode($bytes);
    }

    /**
     * B-8
     */
    public static function encodeInLowercase(string $bytes): string
    {
        return self::inLowercase(rawurlencode($bytes));
    }

    public static function inLowercase(string $encoded): string
    {
        $lowercase = preg_replace_callback(
            '~%[0-9A-F]{2}~',
            static fn (array $escape): string => strtolower($escape[0]),
            $encoded,
        );
        if (! is_string($lowercase)) {
            throw new LogicException('PCRE failed on a value of the tests.');
        }

        return $lowercase;
    }

    public function with(string $name, string $value): self
    {
        return new self([...$this->parameters, [$name, $value]]);
    }

    public function withRelayState(string $relayState): self
    {
        return $this->with('RelayState', self::encode($relayState));
    }

    public function withSigAlg(SignatureAlgorithm $algorithm): self
    {
        return $this->with('SigAlg', self::encode($algorithm->value));
    }

    /**
     * B-2
     *
     * @param 'idp'|'sp' $key
     */
    public function signed(string $key = 'sp', SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256): self
    {
        $query = $this->withSigAlg($algorithm);

        return $query->signedOver($query->octets(), $key, $algorithm);
    }

    /**
     * @param 'idp'|'sp' $key
     */
    public function signedOver(
        string $octets,
        string $key = 'sp',
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
    ): self {
        return $this->with(
            'Signature',
            self::encode(base64_encode(TestKeys::signingKey($key)->sign($octets, $algorithm))),
        );
    }

    /**
     * SAML Bindings §3.4.4.1
     */
    public function octets(): string
    {
        $message = array_values(array_filter(
            $this->parameters,
            static fn (array $parameter): bool => $parameter[0] === 'SAMLRequest' || $parameter[0] === 'SAMLResponse',
        ))[0] ?? throw new LogicException('The query string of the test carries no message parameter.');
        $relayState = $this->has('RelayState') ? '&RelayState=' . $this->value('RelayState') : '';

        return $message[0] . '=' . $message[1] . $relayState . '&SigAlg=' . $this->value('SigAlg');
    }

    public function value(string $name): string
    {
        foreach ($this->parameters as [$parameter, $value]) {
            if ($parameter === $name) {
                return $value;
            }
        }

        throw new LogicException(sprintf('The query string of the test has no %s.', $name));
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_map(static fn (array $parameter): string => $parameter[0], $this->parameters);
    }

    public function replaced(string $name, string $value): self
    {
        return new self(array_map(
            static fn (array $parameter): array => $parameter[0] === $name ? [$name, $value] : $parameter,
            $this->parameters,
        ));
    }

    public function without(string $name): self
    {
        return new self(array_values(array_filter(
            $this->parameters,
            static fn (array $parameter): bool => $parameter[0] !== $name,
        )));
    }

    /**
     * @param list<string> $names
     */
    public function inOrder(array $names): self
    {
        return new self(array_map(fn (string $name): array => [$name, $this->value($name)], $names));
    }

    public function toString(): string
    {
        return implode('&', array_map(
            static fn (array $parameter): string => $parameter[0] . '=' . $parameter[1],
            $this->parameters,
        ));
    }

    private function has(string $name): bool
    {
        foreach ($this->parameters as [$parameter]) {
            if ($parameter === $name) {
                return true;
            }
        }

        return false;
    }
}
