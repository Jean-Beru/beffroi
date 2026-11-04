<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function array_map;
use function array_reverse;
use function base64_decode;
use function base64_encode;
use function bin2hex;
use function chr;
use function chunk_split;
use function count;
use function deflate_add;
use function deflate_init;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function gzdeflate;
use function implode;
use function in_array;
use function intdiv;
use function is_string;
use LogicException;
use function ord;
use function preg_match;
use function preg_match_all;
use function rawurlencode;
use function sprintf;
use function str_repeat;
use function str_replace;
use function str_split;
use function str_contains;
use function str_starts_with;
use function strlen;
use function strpos;
use function strtoupper;
use function strtr;
use function substr;
use function urldecode;
use function urlencode;
use const ZLIB_ENCODING_DEFLATE;
use const ZLIB_ENCODING_RAW;
use const ZLIB_FINISH;
use const ZLIB_FIXED;
use const ZLIB_FULL_FLUSH;
use const ZLIB_SYNC_FLUSH;

/**
 * Section 9.8
 */
final readonly class AdversarialQueryBuilder
{
    public const string FORGED_ID = '_f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

    public const array REAL_QUERIES = [
        'simplesamlphp-authn-request' => 'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-query-2026-10-01.txt',
        'keycloak-authn-request' => 'real/keycloak-26.7.4-sp-authnrequest-to-bindings-query-2026-10-01.txt',
        'simplesamlphp-logout-response' => 'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-query-2026-10-01.txt',
        'keycloak-logout-response' => 'real/keycloak-26.7.4-idp-logoutresponse-to-bindings-query-2026-10-01.txt',
    ];

    public const array REAL_FORMS = [
        'simplesamlphp-response' => 'real/simplesamlphp-2.5.3.1-idp-response-to-bindings-form-2026-10-01.txt',
        'keycloak-response' => 'real/keycloak-26.7.4-idp-response-to-bindings-form-2026-10-01.txt',
    ];

    public const array REAL_CAPTURES = [...self::REAL_QUERIES, ...self::REAL_FORMS];

    private const string AUTHN_REQUEST = 'behaviour/authn-request-unsigned.xml';

    private const string AUTHN_REQUEST_ID = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    private const string LOGOUT_REQUEST = 'behaviour/logout-request-written-for-http-redirect.xml';

    private const string LOGOUT_RESPONSE = 'behaviour/logout-response-written-for-http-redirect.xml';

    private const string RESPONSE = 'behaviour/response-signed-assertion-accepted.xml';

    private const string DEFLATE = 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE';

    private const string RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    private const string BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    /**
     * @return array<string, string> bytes keyed by path under tests/saml2-bindings/Fixture/
     */
    public static function fixtures(): array
    {
        return [
            ...self::names(),
            ...self::separators(),
            ...self::values(),
            ...self::confusion(),
            ...self::encodings(),
            ...self::algorithms(),
            ...self::base64(),
            ...self::deflate(),
            ...self::relayStates(),
            ...self::forms(),
            ...self::bounds(),
            ...self::realCaptures(),
        ];
    }

    public static function write(string $directory): void
    {
        foreach (self::fixtures() as $path => $bytes) {
            if (file_put_contents($directory . '/' . $path, $bytes) === false) {
                throw new LogicException(sprintf('%s could not be written.', $path));
            }
        }
    }

    public static function refused(string $attempt): string
    {
        return 'hostile/adversarial-' . $attempt . '-refused.txt';
    }

    public static function accepted(string $attempt): string
    {
        return 'behaviour/adversarial-' . $attempt . '-accepted.txt';
    }

    /**
     * Section 3 rows 1 and 2, B-1
     *
     * @return array<string, string>
     */
    private static function names(): array
    {
        $signed = self::signedAuthnRequest()->toString();
        $forged = RedirectQuery::message(self::forgedAuthnRequest());
        $message = RedirectQuery::message(self::fixture(self::AUTHN_REQUEST));
        $query = self::signedAuthnRequest();
        $logoutRequest = RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST))->withRelayState('state')->signed('idp');

        return [
            self::accepted('name-double-percent-encoded-saml-request') => self::nextTo(
                $signed,
                'SAML%2552equest',
                $forged,
            ),
            self::refused('name-double-percent-encoded-saml-request-alone') => 'SAML%2552equest=' . $message,
            self::refused('name-double-percent-encoded-sig-alg-in-place-of-sig-alg') => $query
                ->without('SigAlg')
                ->without('Signature')
                ->with('Sig%2541lg', $query->value('SigAlg'))
                ->with('Signature', $query->value('Signature'))
                ->toString(),
            self::refused('name-nul-after-saml-request') => self::nextTo($signed, 'SAMLRequest%00', $forged),
            self::refused('name-nul-after-saml-request-alone') => 'SAMLRequest%00=' . $message,
            self::refused('name-nul-and-a-letter-after-saml-request') => self::nextTo(
                $signed,
                'SAMLRequest%00x',
                $forged,
            ),
            self::refused('name-nul-after-relay-state') => self::nextTo($signed, 'RelayState%00', 'forged'),
            self::accepted('name-nul-inside-saml-request') => self::nextTo($signed, 'SAML%00Request', $forged),
            self::accepted('name-nul-alone') => self::nextTo($signed, '%00', 'x'),
            self::accepted('name-overlong-utf8-e-in-saml-request') => self::nextTo(
                $signed,
                'SAMLR%C1%A5quest',
                $forged,
            ),
            self::accepted('name-overlong-utf8-nul-after-saml-request') => self::nextTo(
                $signed,
                'SAMLRequest%C0%80',
                $forged,
            ),
            self::accepted('name-invalid-utf8-after-saml-request') => self::nextTo($signed, 'SAMLRequest%FF', $forged),
            self::accepted('name-lower-case-saml-request') => self::nextTo($signed, 'samlrequest', $forged),
            self::refused('name-lower-case-saml-request-alone') => 'samlrequest=' . $message,
            self::accepted('name-upper-case-relay-state') => self::nextTo($signed, 'RELAYSTATE', 'forged'),
            self::accepted('name-lower-case-sig-alg-and-signature') => RedirectQuery::carrying(
                'SAMLRequest',
                self::fixture(self::AUTHN_REQUEST),
            )
                ->withRelayState('state')
                ->with('sigalg', $query->value('SigAlg'))
                ->with('signature', $query->value('Signature'))
                ->toString(),
            self::refused('name-lower-case-sig-alg-and-signature-logout-request') => RedirectQuery::carrying(
                'SAMLRequest',
                self::fixture(self::LOGOUT_REQUEST),
            )
                ->withRelayState('state')
                ->with('sigalg', $logoutRequest->value('SigAlg'))
                ->with('signature', $logoutRequest->value('Signature'))
                ->toString(),
            self::accepted('name-cyrillic-e-in-saml-request') => self::nextTo($signed, 'SAMLR%D0%B5quest', $forged),
            self::refused('name-cyrillic-e-in-saml-request-alone') => 'SAMLR%D0%B5quest=' . $message,
            self::accepted('name-cyrillic-a-in-relay-state') => self::nextTo($signed, 'Rel%D0%B0yState', 'forged'),
            self::accepted('name-fullwidth-s-in-saml-request') => self::nextTo($signed, '%EF%BC%B3AMLRequest', $forged),
            self::accepted('name-space-after-saml-request-written-plus') => self::nextTo(
                $signed,
                'SAMLRequest+',
                $forged,
            ),
            self::accepted('name-space-after-saml-request-written-escaped') => self::nextTo(
                $signed,
                'SAMLRequest%20',
                $forged,
            ),
            self::refused('name-space-before-saml-request-written-plus') => self::nextTo(
                $signed,
                '+SAMLRequest',
                $forged,
            ),
            self::refused('name-space-before-saml-request-written-escaped') => self::nextTo(
                $signed,
                '%20SAMLRequest',
                $forged,
            ),
            self::refused('name-space-before-saml-request-written-raw') => self::nextTo(
                $signed,
                ' SAMLRequest',
                $forged,
            ),
            self::accepted('name-tab-before-saml-request') => self::nextTo($signed, '%09SAMLRequest', $forged),
            self::refused('name-brackets-after-saml-request') => self::nextTo($signed, 'SAMLRequest[]', $forged),
            self::refused('name-escaped-brackets-after-saml-request') => self::nextTo(
                $signed,
                'SAMLRequest%5B%5D',
                $forged,
            ),
            self::refused('name-index-after-relay-state') => self::nextTo($signed, 'RelayState[0]', 'forged'),
            self::accepted('name-dot-after-saml-request') => self::nextTo($signed, 'SAMLRequest.', $forged),
            self::accepted('name-escaped-equals-after-saml-request') => self::nextTo(
                $signed,
                'SAMLRequest%3D',
                $forged,
            ),
            self::refused('name-escaped-equals-and-the-message-in-the-name-alone') => 'SAMLRequest%3D' . $message,
        ];
    }

    /**
     * Section 3 rows 1 to 3, B-1, B-2, section 6.1 step 2
     *
     * @return array<string, string>
     */
    private static function separators(): array
    {
        $query = self::signedAuthnRequest();
        $signed = $query->toString();
        $logoutRequest = RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST))->withRelayState('state')->signed('idp')->toString();
        $segments = explode('&', $signed);

        return [
            self::refused('separator-semicolon-before-relay-state') => str_replace(
                '&RelayState=',
                ';RelayState=',
                $signed,
            ),
            self::refused('separator-semicolon-before-sig-alg') => str_replace('&SigAlg=', ';SigAlg=', $signed),
            self::refused('separator-semicolon-before-signature') => str_replace('&Signature=', ';Signature=', $signed),
            self::accepted('separator-semicolon-and-a-message-in-relay-state') => self::signedWithRelayState('a;SAMLRequest=x'),
            self::refused('separator-ampersand-entity-before-relay-state') => str_replace(
                '&RelayState=',
                '&amp;RelayState=',
                $signed,
            ),
            self::accepted('separator-ampersand-entity-everywhere') => str_replace('&', '&amp;', $signed),
            self::refused('separator-ampersand-entity-everywhere-logout-request') => str_replace(
                '&',
                '&amp;',
                $logoutRequest,
            ),
            self::accepted('separator-ampersand-entity-escaped-in-relay-state') => self::signedWithRelayState('a%26amp%3Bb'),
            self::accepted('separator-question-mark-in-relay-state') => self::signedWithRelayState('a?b'),
            self::refused('separator-leading-question-mark-kept') => '?' . $signed,
            self::refused('separator-leading-question-mark-kept-message-second') =>
                '?' . $query->inOrder(['RelayState', 'SAMLRequest', 'SigAlg', 'Signature'])->toString(),
            self::accepted('separator-hash-in-relay-state') => self::signedWithRelayState('a#b'),
            self::accepted('separator-hash-escaped-in-relay-state') => self::signedWithRelayState('a%23b'),
            self::accepted('separator-empty-segments-up-to-the-bound') => self::filled(
                implode(str_repeat('&', 1_500), $segments),
                8_192,
            ),
            self::accepted('separator-sixty-thousand-empty-segments-under-the-ceiling') => self::filled(
                implode(str_repeat('&', 20_000), $segments),
                65_536,
            ),
            self::accepted('separator-a-thousand-and-one-other-parameters-first') => str_repeat('a=&', 1_001) . $signed,
        ];
    }

    /**
     * B-8, section 6.1 steps 3 to 5 and 8
     *
     * @return array<string, string>
     */
    private static function values(): array
    {
        $message = RedirectQuery::message(self::fixture(self::AUTHN_REQUEST));
        $query = self::signedAuthnRequest();
        $signature = $query->value('Signature');

        return [
            self::refused('value-space-before-the-message') => 'SAMLRequest=+' . $message,
            self::refused('value-space-after-the-message') => 'SAMLRequest=' . $message . '%20',
            self::refused('value-nul-after-the-message') => 'SAMLRequest=' . $message . '%00',
            self::refused('value-double-percent-encoded-message') => 'SAMLRequest=' . rawurlencode($message),
            self::refused('value-space-before-the-signature') => $query->replaced('Signature', '+' . $signature)->toString(),
            self::refused('value-nul-after-the-signature') => $query->replaced('Signature', $signature . '%00')->toString(),
            self::refused('value-double-percent-encoded-signature') => $query->replaced('Signature', rawurlencode($signature))->toString(),
            self::refused('value-space-after-saml-encoding') => $query->with('SAMLEncoding', RedirectQuery::encode(self::DEFLATE) . '+')->toString(),
            self::refused('value-nul-after-saml-encoding') => $query->with('SAMLEncoding', RedirectQuery::encode(self::DEFLATE) . '%00')->toString(),
            self::refused('value-double-percent-encoded-saml-encoding') => $query
                ->with('SAMLEncoding', rawurlencode(RedirectQuery::encode(self::DEFLATE)))
                ->toString(),
        ];
    }

    /**
     * Section 3 rows 1 and 3, B-1, B-2, B-5, CVE-2025-27773
     *
     * @return array<string, string>
     */
    private static function confusion(): array
    {
        $query = self::signedAuthnRequest();
        $forged = RedirectQuery::message(self::forgedAuthnRequest());
        $logoutResponse = RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE))->withRelayState('state')->signed()->toString();
        $logoutRequest = RedirectQuery::message(self::fixture(self::LOGOUT_REQUEST));
        $spaced = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))->with('RelayState', 'a+b')->signed();
        $sha512 = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))
            ->withRelayState('state')
            ->with('SigAlg', RedirectQuery::encode('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'));

        return [
            self::refused('confusion-saml-request-twice-in-two-spellings') => $query
                ->with('SAMLRequest', RedirectQuery::inLowercase($query->value('SAMLRequest')))
                ->toString(),
            self::refused('confusion-signed-logout-response-and-a-logout-request-under-a-space') => $logoutResponse . '&+SAMLRequest=' . $logoutRequest,
            self::refused('confusion-signed-logout-response-and-a-logout-request-under-a-nul') => $logoutResponse . '&SAMLRequest%00=' . $logoutRequest,
            self::refused('confusion-signed-logout-response-and-a-logout-request-under-brackets') => $logoutResponse . '&SAMLRequest[]=' . $logoutRequest,
            self::accepted('confusion-forged-message-under-a-longer-name-first') => 'xSAMLRequest=' . $forged . '&' . $query->toString(),
            self::accepted('confusion-forged-message-inside-another-value-first') =>
                'tenant=' . rawurlencode('SAMLRequest=' . $forged) . '&' . $query->toString(),
            self::refused('confusion-relay-state-folded-into-the-message') => RedirectQuery::none()
                ->with('SAMLRequest', $query->value('SAMLRequest') . '%26RelayState%3Dstate')
                ->with('SigAlg', $query->value('SigAlg'))
                ->with('Signature', $query->value('Signature'))
                ->toString(),
            self::accepted('confusion-relay-state-holding-what-a-decoding-parser-reads-as-sig-alg') => self::signedWithRelayState('a%26SigAlg%3Dx'),
            self::refused('confusion-message-escaped-again-after-signing') => $query
                ->replaced('SAMLRequest', RedirectQuery::inLowercase($query->value('SAMLRequest')))
                ->toString(),
            self::refused('confusion-relay-state-space-written-again-after-signing') => $spaced->replaced('RelayState', 'a%20b')->toString(),
            self::refused('confusion-sig-alg-escaped-again-after-signing') => $query
                ->replaced('SigAlg', RedirectQuery::inLowercase($query->value('SigAlg')))
                ->toString(),
            self::accepted('confusion-signature-escaped-again-after-signing') => $query
                ->replaced('Signature', RedirectQuery::inLowercase($query->value('Signature')))
                ->toString(),
            self::refused('confusion-sig-alg-of-sha512-over-a-signature-under-sha256') => $sha512->signedOver($sha512->octets())->toString(),
        ];
    }

    /**
     * Section 8, section 6.1 step 4, SAML Bindings §3.4.4
     *
     * @return array<string, string>
     */
    private static function encodings(): array
    {
        $query = self::signedAuthnRequest();
        $deflate = RedirectQuery::encode(self::DEFLATE);

        return [
            self::accepted('encoding-deflate-every-byte-escaped') => $query->with('SAMLEncoding', self::escapedWhole(self::DEFLATE))->toString(),
            self::accepted('encoding-deflate-in-lower-case-hexadecimal') => $query
                ->with('SAMLEncoding', RedirectQuery::encodeInLowercase(self::DEFLATE))
                ->toString(),
            self::accepted('encoding-deflate-unescaped') => $query->with('SAMLEncoding', self::DEFLATE)->toString(),
            self::accepted('encoding-deflate-first-of-a-signed-query-string') => 'SAMLEncoding=' . $deflate . '&' . $query->toString(),
            self::refused('encoding-deflate-over-a-message-not-deflated') =>
                'SAMLRequest=' . RedirectQuery::encode(base64_encode(self::fixture(self::AUTHN_REQUEST))) . '&SAMLEncoding=' . $deflate,
            self::refused('encoding-deflate-in-upper-case') => $query->with('SAMLEncoding', RedirectQuery::encode(strtoupper(self::DEFLATE)))->toString(),
            self::refused('encoding-deflate-with-a-trailing-slash') => $query->with('SAMLEncoding', $deflate . '%2F')->toString(),
            self::accepted('encoding-name-in-lower-case-holding-another-uri') => $query
                ->with('samlencoding', RedirectQuery::encode('urn:example:encoding'))
                ->toString(),
        ];
    }

    /**
     * Section 3 row 4, B-3, D-5, SAML Bindings §3.4.4.1
     *
     * @return array<string, string>
     */
    private static function algorithms(): array
    {
        $query = self::signedAuthnRequest();
        $encoded = RedirectQuery::encode(self::RSA_SHA256);

        return [
            self::refused('sig-alg-fragment-in-upper-case') => self::withSigAlg(
                $query,
                RedirectQuery::encode('http://www.w3.org/2001/04/xmldsig-more#RSA-SHA256'),
            ),
            self::refused('sig-alg-scheme-in-upper-case') => self::withSigAlg(
                $query,
                RedirectQuery::encode('HTTP://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
            ),
            self::refused('sig-alg-host-in-upper-case') => self::withSigAlg(
                $query,
                RedirectQuery::encode('http://WWW.W3.ORG/2001/04/xmldsig-more#rsa-sha256'),
            ),
            self::refused('sig-alg-https-scheme') => self::withSigAlg(
                $query,
                RedirectQuery::encode('https://www.w3.org/2001/04/xmldsig-more#rsa-sha256'),
            ),
            self::refused('sig-alg-trailing-slash') => self::withSigAlg($query, $encoded . '%2F'),
            self::refused('sig-alg-space-before') => self::withSigAlg($query, '+' . $encoded),
            self::refused('sig-alg-space-after') => self::withSigAlg($query, $encoded . '%20'),
            self::refused('sig-alg-tab-after') => self::withSigAlg($query, $encoded . '%09'),
            self::refused('sig-alg-line-feed-after') => self::withSigAlg($query, $encoded . '%0A'),
            self::refused('sig-alg-no-break-space-after') => self::withSigAlg($query, $encoded . '%C2%A0'),
            self::refused('sig-alg-nul-after') => self::withSigAlg($query, $encoded . '%00'),
            self::refused('sig-alg-double-percent-encoded') => self::withSigAlg($query, rawurlencode($encoded)),
            self::refused('sig-alg-sha256-under-the-namespace-of-sha1') => self::withSigAlg(
                $query,
                RedirectQuery::encode('http://www.w3.org/2000/09/xmldsig#rsa-sha256'),
            ),
            self::refused('sig-alg-rsa-sha224') => self::withSigAlg(
                $query,
                RedirectQuery::encode('http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'),
            ),
            self::refused('sig-alg-rsa-pkcs1-encryption') => self::withSigAlg(
                $query,
                RedirectQuery::encode('http://www.w3.org/2001/04/xmlenc#rsa-1_5'),
            ),
            self::accepted('sig-alg-in-lower-case-hexadecimal-signed-as-sent') => self::signedWithSigAlg(
                RedirectQuery::inLowercase($encoded),
            ),
            self::accepted('sig-alg-every-byte-escaped-signed-as-sent') => self::signedWithSigAlg(self::escapedWhole(self::RSA_SHA256)),
            self::accepted('sig-alg-unescaped-but-its-hash-signed-as-sent') => self::signedWithSigAlg(str_replace(
                '#',
                '%23',
                self::RSA_SHA256,
            )),
        ];
    }

    /**
     * B-8, section 6.1 steps 5 and 8
     *
     * @return array<string, string>
     */
    private static function base64(): array
    {
        $deflated = self::deflated(self::fixture(self::AUTHN_REQUEST));
        $base64 = base64_encode($deflated);
        $query = self::signedAuthnRequest();
        $signatureText = self::decoded($query->value('Signature'));

        return [
            self::refused('base64-padding-in-the-middle-of-the-message') =>
                'SAMLRequest=' . RedirectQuery::encode(base64_encode($deflated[0]) . base64_encode(substr($deflated, 1))),
            self::refused('base64-padding-in-the-middle-of-the-signature') => $query
                ->replaced('Signature', RedirectQuery::encode(
                    base64_encode(substr(self::decodedBase64($signatureText), 0, 1)) . base64_encode(substr(self::decodedBase64($signatureText), 1)),
                ))
                ->toString(),
            self::refused('base64-carriage-return-and-line-feed-in-the-message') => 'SAMLRequest=' . RedirectQuery::encode(chunk_split($base64, 76, "\r\n")),
            self::refused('base64-unused-bit-set-in-the-signature') => $query
                ->replaced('Signature', RedirectQuery::encode(self::withAnUnusedBitSet($signatureText)))
                ->toString(),
            self::refused('base64-url-safe-alphabet-in-the-signature') => $query
                ->replaced('Signature', str_replace(['+', '/'], ['-', '_'], $signatureText))
                ->toString(),
            self::accepted('base64-slash-and-padding-unescaped-signed-as-sent') => self::signedMessage(str_replace(
                '+',
                '%2B',
                $base64,
            )),
            self::accepted('base64-every-character-escaped-signed-as-sent') => self::signedMessage(self::escapedWhole($base64)),
        ];
    }

    /**
     * Section 3 rows 7 and 8, B-7, B-8, RFC 1951, RFC 1950
     *
     * @return array<string, string>
     */
    private static function deflate(): array
    {
        $xml = self::fixture(self::AUTHN_REQUEST);
        $deflated = self::deflated($xml);
        $level0 = gzdeflate($xml, 0, ZLIB_ENCODING_RAW);
        $stored = deflate_init(ZLIB_ENCODING_RAW, ['level' => 0]);
        $fixed = deflate_init(ZLIB_ENCODING_RAW, ['strategy' => ZLIB_FIXED]);
        $zlibDictionary = deflate_init(ZLIB_ENCODING_DEFLATE, ['dictionary' => 'urn:oasis:names:tc:SAML:2.0:protocol']);
        $rawDictionary = deflate_init(ZLIB_ENCODING_RAW, ['dictionary' => 'urn:oasis:names:tc:SAML:2.0:protocol']);
        $flushed = deflate_init(ZLIB_ENCODING_RAW);
        if (! is_string($level0) || $stored === false || $fixed === false || $zlibDictionary === false || $rawDictionary === false || $flushed === false) {
            throw new LogicException('zlib could not deflate an attempt.');
        }
        $chunks = '';
        foreach (str_split($xml, 7) as $chunk) {
            $chunks .= self::added(deflate_add($stored, $chunk, ZLIB_FULL_FLUSH));
        }
        $chunks .= self::added(deflate_add($stored, '', ZLIB_FINISH));
        $last = ord($deflated[strlen($deflated) - 1]);
        if (($last & 0x80) !== 0) {
            throw new LogicException('The last byte of the stream already has its high bit set.');
        }
        $emptyBlock = "\x00\x00\x00\xFF\xFF";

        return [
            self::accepted('deflate-stored-blocks') => self::signedMessage(RedirectQuery::encode(base64_encode($level0))),
            self::accepted('deflate-stored-blocks-of-seven-bytes') => self::signedMessage(RedirectQuery::encode(
                base64_encode($chunks),
            )),
            self::accepted('deflate-fixed-codes') => self::signedMessage(RedirectQuery::encode(base64_encode(self::added(
                deflate_add($fixed, $xml, ZLIB_FINISH),
            )))),
            self::accepted('deflate-five-hundred-empty-stored-blocks-first') => self::signedMessage(RedirectQuery::encode(
                base64_encode(str_repeat($emptyBlock, 500) . $deflated),
            )),
            self::accepted('deflate-five-thousand-empty-stored-blocks-first-under-the-ceiling') => self::signedMessage(
                RedirectQuery::encode(base64_encode(str_repeat($emptyBlock, 5_000) . $deflated)),
            ),
            self::accepted('deflate-high-bit-after-the-final-block-set') => self::signedMessage(RedirectQuery::encode(
                base64_encode(substr($deflated, 0, -1) . chr($last | 0x80)),
            )),
            self::refused('deflate-two-final-blocks') => self::unsignedMessage($deflated . $deflated),
            self::refused('deflate-empty-final-block-after-the-final-block') => self::unsignedMessage($deflated . "\x03\x00"),
            self::refused('deflate-zlib-preset-dictionary') => self::unsignedMessage(self::added(deflate_add(
                $zlibDictionary,
                $xml,
                ZLIB_FINISH,
            ))),
            self::refused('deflate-raw-against-a-preset-dictionary') => self::unsignedMessage(self::added(deflate_add(
                $rawDictionary,
                $xml,
                ZLIB_FINISH,
            ))),
            self::refused('deflate-reserved-block-type') => self::unsignedMessage("\x07" . $deflated),
            self::refused('deflate-stored-block-length-and-complement-disagree') => self::unsignedMessage("\x01\x05\x00\x00\x00abcde"),
            self::refused('deflate-flushed-without-a-final-block') => self::unsignedMessage(self::added(deflate_add(
                $flushed,
                $xml,
                ZLIB_SYNC_FLUSH,
            ))),
            self::refused('deflate-empty-stream') => self::unsignedMessage("\x03\x00"),
        ];
    }

    /**
     * Section 3 row 10, B-9, SAML Bindings §3.4.3
     *
     * @return array<string, string>
     */
    private static function relayStates(): array
    {
        return [
            self::accepted('relay-state-carriage-return-and-line-feed') => self::signedWithRelayState('a%0D%0Ab'),
            self::accepted('relay-state-nul') => self::signedWithRelayState('sta%00te'),
            self::accepted('relay-state-a-nul-alone') => self::signedWithRelayState('%00'),
            self::accepted('relay-state-html') => self::signedWithRelayState(RedirectQuery::encode('<script>alert(1)</script>')),
            self::accepted('relay-state-url-of-another-site') => self::signedWithRelayState(RedirectQuery::encode('https://attacker.example.com/')),
            self::accepted('relay-state-invalid-utf8') => self::signedWithRelayState('%FF%FE'),
            self::accepted('relay-state-utf8-unescaped') => self::signedWithRelayState("\u{e9}t\u{e9}"),
            self::accepted('relay-state-space-before') => self::signedWithRelayState('+state'),
            self::accepted('relay-state-space-after') => self::signedWithRelayState('state%20'),
            self::accepted('relay-state-a-space-alone') => self::signedWithRelayState('+'),
            self::accepted('relay-state-double-percent-encoded') => self::signedWithRelayState('%2573tate'),
            self::accepted('relay-state-80-bytes-written-in-240-characters') => self::signedWithRelayState(
                self::escapedWhole(str_repeat('r', 80)),
            ),
            self::accepted('relay-state-80-spaces-written-plus') => self::signedWithRelayState(str_repeat('+', 80)),
            self::accepted('relay-state-81-spaces-written-plus') => self::signedWithRelayState(str_repeat('+', 81)),
            self::accepted('relay-state-80-bytes-of-characters-of-three-bytes-and-two-letters') => self::signedWithRelayState(RedirectQuery::encode(
                str_repeat("\u{20ac}", 26) . 'ab',
            )),
            self::accepted('relay-state-81-bytes-ending-with-a-character-of-two-bytes') => self::signedWithRelayState(RedirectQuery::encode(
                str_repeat('a', 79) . "\u{e9}",
            )),
        ];
    }

    /**
     * Section 3 rows 1, 7, 8 and 10, B-1, B-7, B-8, B-9, section 6.2
     *
     * @return array<string, string>
     */
    private static function forms(): array
    {
        $base64 = base64_encode(self::fixture(self::RESPONSE));
        $field = urlencode($base64);
        $message = 'SAMLResponse=' . $field;

        return [
            self::refused('form-index-after-saml-response') => 'SAMLResponse[0]=' . $field,
            self::refused('form-two-keys-after-saml-response') => 'SAMLResponse[a][b]=' . $field,
            self::refused('form-escaped-brackets-after-saml-response') => 'SAMLResponse%5B%5D=' . $field,
            self::refused('form-brackets-after-saml-request-next-to-saml-response') => 'SAMLRequest[]=x&' . $message,
            self::accepted('form-numeric-names-first') => '0=a&1=b&' . $message,
            self::accepted('form-lower-case-saml-response-next-to-the-message') => 'samlresponse=x&' . $message,
            self::refused('form-lower-case-saml-response-alone') => 'samlresponse=' . $field,
            self::accepted('form-space-before-saml-response') => '+SAMLResponse=' . $field,
            self::accepted('form-nul-after-saml-response') => 'SAMLResponse%00=' . $field,
            self::refused('form-dot-after-saml-response') => 'SAMLResponse.=' . $field,
            self::accepted('form-saml-encoding') => $message . '&SAMLEncoding=' . urlencode(self::DEFLATE),
            self::refused('form-brackets-after-signature') => $message . '&Signature[]=x',
            self::accepted('form-lower-case-sig-alg') => $message . '&sigalg=' . urlencode(self::RSA_SHA256),
            self::refused('form-empty-sig-alg') => $message . '&SigAlg=',
            self::accepted('form-saml-response-twice-the-last-genuine') => 'SAMLResponse=x&' . $message,
            self::accepted('form-wrapped-by-carriage-returns-alone') => 'SAMLResponse=' . urlencode(chunk_split($base64, 76, "\r")),
            self::accepted('form-line-feed-every-three-characters') => 'SAMLResponse=' . urlencode(chunk_split($base64, 3, "\n")),
            self::accepted('form-line-breaks-at-both-ends') => 'SAMLResponse=' . urlencode("\r\n" . $base64 . "\r\n"),
            self::refused('form-form-feed-in-the-message') => 'SAMLResponse=' . urlencode("\f" . $base64),
            self::refused('form-vertical-tab-in-the-message') => 'SAMLResponse=' . urlencode("\v" . $base64),
            self::refused('form-no-break-space-in-the-message') => 'SAMLResponse=' . urlencode("\u{a0}" . $base64),
            self::refused('form-nul-in-the-message') => 'SAMLResponse=' . urlencode($base64 . "\0"),
            self::refused('form-padding-in-the-middle-of-the-message') => 'SAMLResponse='
                . urlencode(
                    base64_encode(substr(self::fixture(self::RESPONSE), 0, 1))
                        . base64_encode(substr(
                            self::fixture(self::RESPONSE),
                            1,
                        )),
                ),
            self::refused('form-message-percent-encoded-twice') => 'SAMLResponse=' . urlencode($field),
            self::refused('form-plus-left-unescaped-in-the-message') => 'SAMLResponse=' . self::withPlus($base64),
            self::accepted('form-relay-state-carriage-return-and-line-feed') => $message . '&RelayState=a%0D%0Ab',
            self::accepted('form-relay-state-nul') => $message . '&RelayState=sta%00te',
            self::accepted('form-relay-state-html') => $message . '&RelayState=' . urlencode('<script>alert(1)</script>'),
            self::accepted('form-relay-state-80-bytes-of-characters-of-three-bytes-and-two-letters') =>
                $message . '&RelayState=' . urlencode(str_repeat("\u{20ac}", 26) . 'ab'),
            self::accepted('form-relay-state-81-bytes-ending-with-a-character-of-two-bytes') =>
                $message . '&RelayState=' . urlencode(str_repeat('a', 79) . "\u{e9}"),
            self::accepted('form-message-of-exactly-max-form-value-bytes') => $message,
            self::refused('form-message-one-byte-over-max-form-value-bytes') => $message,
            self::refused('form-message-under-max-form-value-bytes-its-line-breaks-over') => 'SAMLResponse=' . urlencode(chunk_split($base64, 76, "\r\n")),
        ];
    }

    /**
     * Section 7, B-7, D-14
     *
     * @return array<string, string>
     */
    private static function bounds(): array
    {
        $query = self::signedAuthnRequest();
        $at1024 = base64_encode(str_repeat("\x5A", 1_024));
        if (strlen($at1024) !== 1_368) {
            throw new LogicException('The base64 of 1 024 bytes is 1 368 characters.');
        }

        return [
            self::accepted('bound-query-string-of-exactly-the-ceiling') => self::filled(
                $query->toString(),
                65_536,
                'x',
            ),
            self::refused('bound-query-string-one-byte-over-the-ceiling') => self::filled(
                $query->toString(),
                65_537,
                'x',
            ),
            self::refused('bound-signature-of-1024-bytes-in-1368-characters') => $query->replaced('Signature', RedirectQuery::encode($at1024))->toString(),
            self::refused('bound-signature-of-1368-characters-written-in-4104') => $query->replaced('Signature', self::escapedWhole($at1024))->toString(),
            self::refused('bound-signature-of-256-bytes') => $query
                ->replaced('Signature', RedirectQuery::encode(base64_encode(str_repeat("\x5A", 256))))
                ->toString(),
        ];
    }

    /**
     * Section 9.4, B-2, B-3, B-9
     *
     * @return array<string, string>
     */
    private static function realCaptures(): array
    {
        $attempts = [];
        foreach (self::REAL_QUERIES as $capture => $path) {
            $query = RedirectQuery::of(self::fixture($path));
            $message = $query->names()[0];
            foreach ([
                $message => 'message',
                'RelayState' => 'relay-state',
                'SigAlg' => 'sig-alg',
                'Signature' => 'signature',
            ] as $name => $part) {
                $escaped = 'real-' . $capture . '-' . $part . '-one-character-escaped';
                $attempts[$name === 'Signature' ? self::accepted($escaped) : self::refused($escaped)] = $query
                    ->replaced($name, self::withOneCharacterEscaped($query->value($name)))
                    ->toString();
                $attempts[self::refused('real-' . $capture . '-' . $part . '-one-character-changed')] = $query
                    ->replaced(
                        $name,
                        in_array($name, [$message, 'Signature'], true)
                            ? self::withTheMiddleCharacterChanged($query->value($name))
                            : self::withTheFirstCharacterChanged($query->value($name)),
                    )
                    ->toString();
            }
            $attempts[self::accepted('real-' . $capture . '-parameters-in-reverse-order')] = $query->inOrder(array_reverse($query->names()))->toString();
            $attempts[self::accepted('real-' . $capture . '-saml-encoding-added')] = $query
                ->with('SAMLEncoding', RedirectQuery::encode(self::DEFLATE))
                ->toString();
        }
        foreach (self::REAL_FORMS as $capture => $path) {
            [$message, $relayState] = explode('&', self::fixture($path));
            $attempts[self::refused('real-' . $capture . '-message-one-character-changed')] =
                self::withTheMiddleCharacterChanged($message, 'SAMLResponse=') . '&' . $relayState;
            $attempts[self::accepted('real-' . $capture . '-relay-state-one-character-changed')] =
                $message . '&' . self::withTheFirstCharacterChanged($relayState, 'RelayState=');
        }

        return $attempts;
    }

    private static function nextTo(string $signed, string $name, string $value): string
    {
        return $signed . '&' . $name . '=' . $value;
    }

    private static function withSigAlg(RedirectQuery $query, string $sigAlg): string
    {
        return $query->replaced('SigAlg', $sigAlg)->toString();
    }

    private static function signedWithSigAlg(string $sigAlg): string
    {
        $query = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))->withRelayState('state')->with('SigAlg', $sigAlg);

        return $query->signedOver($query->octets())->toString();
    }

    private static function signedAuthnRequest(): RedirectQuery
    {
        return RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))->withRelayState('state')->signed();
    }

    private static function signedWithRelayState(string $raw): string
    {
        return RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))->with('RelayState', $raw)->signed()->toString();
    }

    private static function signedMessage(string $raw): string
    {
        return RedirectQuery::none()->with('SAMLRequest', $raw)->withRelayState('state')->signed()->toString();
    }

    private static function unsignedMessage(string $deflated): string
    {
        return 'SAMLRequest=' . RedirectQuery::encode(base64_encode($deflated));
    }

    private static function forgedAuthnRequest(): string
    {
        return str_replace(self::AUTHN_REQUEST_ID, self::FORGED_ID, self::fixture(self::AUTHN_REQUEST));
    }

    private static function filled(string $query, int $length, string $filler = '&'): string
    {
        $padding = $length - strlen($query);
        if ($padding < 2) {
            throw new LogicException('The query string of an attempt is already longer than its bound.');
        }

        return $filler === '&'
            ? $query . str_repeat('&', $padding)
            : $query . '&' . str_repeat($filler, $padding - 1);
    }

    private static function escapedWhole(string $bytes): string
    {
        return implode('', array_map(
            static fn (string $byte): string => '%' . strtoupper(bin2hex($byte)),
            str_split($bytes),
        ));
    }

    private static function withOneCharacterEscaped(string $raw): string
    {
        $characters = self::characters($raw);
        foreach ($characters as $index => $character) {
            if (preg_match('~^[A-Za-z0-9]$~', $character) !== 1) {
                continue;
            }
            $characters[$index] = '%' . strtoupper(bin2hex($character));

            return implode('', $characters);
        }

        throw new LogicException('A value of a real capture holds no letter or digit.');
    }

    private static function withTheFirstCharacterChanged(string $raw, string $prefix = ''): string
    {
        return self::withACharacterChanged($raw, $prefix, 0);
    }

    private static function withTheMiddleCharacterChanged(string $raw, string $prefix = ''): string
    {
        return self::withACharacterChanged(
            $raw,
            $prefix,
            intdiv(count(self::characters(substr($raw, strlen($prefix)))), 2),
        );
    }

    private static function withACharacterChanged(string $raw, string $prefix, int $start): string
    {
        if (! str_starts_with($raw, $prefix)) {
            throw new LogicException('A field of a real form is not where the attempt expects it.');
        }
        $characters = self::characters(substr($raw, strlen($prefix)));
        $counter = count($characters);
        for ($index = $start; $index < $counter; ++$index) {
            if (preg_match('~^[A-Za-z0-9]$~', $characters[$index]) !== 1) {
                continue;
            }
            $characters[$index] = strtr(
                $characters[$index],
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                'BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza1234567890',
            );

            return $prefix . implode('', $characters);
        }

        throw new LogicException('A value of a real capture holds no letter or digit after its start.');
    }

    /**
     * @return list<string>
     */
    private static function characters(string $raw): array
    {
        preg_match_all('~%[0-9A-Fa-f]{2}|.~s', $raw, $matches);

        return $matches[0];
    }

    private static function withAnUnusedBitSet(string $text): string
    {
        $padding = strpos($text, '=');
        if ($padding === false) {
            throw new LogicException('The base64 of an attempt has no padding.');
        }
        $last = strpos(self::BASE64, $text[$padding - 1]);
        if ($last === false) {
            throw new LogicException('The base64 of an attempt holds a character outside the alphabet.');
        }

        return substr($text, 0, $padding - 1) . self::BASE64[$last + 1] . substr($text, $padding);
    }

    private static function withPlus(string $base64): string
    {
        if (! str_contains($base64, '+')) {
            throw new LogicException('The base64 of an attempt holds no "+".');
        }

        return str_replace('%2B', '+', urlencode($base64));
    }

    private static function decoded(string $raw): string
    {
        return urldecode($raw);
    }

    private static function decodedBase64(string $text): string
    {
        $bytes = base64_decode($text, true);
        if (! is_string($bytes)) {
            throw new LogicException('The base64 of an attempt is not base64.');
        }

        return $bytes;
    }

    private static function deflated(string $xml): string
    {
        $deflated = gzdeflate($xml, -1, ZLIB_ENCODING_RAW);
        if (! is_string($deflated)) {
            throw new LogicException('zlib could not deflate an attempt.');
        }

        return $deflated;
    }

    private static function added(string|false $deflated): string
    {
        if (! is_string($deflated)) {
            throw new LogicException('zlib could not deflate an attempt.');
        }

        return $deflated;
    }

    private static function fixture(string $path): string
    {
        $bytes = file_get_contents(__DIR__ . '/../Fixture/' . $path);
        if (! is_string($bytes)) {
            throw new LogicException(sprintf('The fixture %s cannot be read.', $path));
        }

        return $bytes;
    }
}
