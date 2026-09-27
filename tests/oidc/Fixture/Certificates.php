<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use function base64_encode;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\ClientJwks;
use LogicException;

/**
 * The certificates of the mutual-TLS tests (RFC 8705 §2), issued once with openssl and kept here as the
 * edge hands them over. Four of them, and each one answers a question:
 *
 * - "client" is signed by a small authority and carries every kind of name of §2.1.2: a subject
 *   distinguished name, a dNSName, a URI, an iPAddress and an rfc822Name, so that the five ways of
 *   registering a client are read out of one certificate.
 * - "other" is signed by the same authority and names somebody else, which is the client that holds a
 *   certificate of the right authority and is refused all the same.
 * - "selfSigned" carries the same names and no authority at all, which is what §2.2 authenticates.
 * - "reissued" is that certificate issued again, same names, another key: another certificate, and
 *   therefore not the one the client published.
 */
final class Certificates
{
    private const string CLIENT_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICHDCCAcOgAwIBAgIBATAKBggqhkjOPQQDAjA6MRYwFAYDVQQDDA1IZWlkaSBU
        ZXN0IENBMRMwEQYDVQQKDApIZWlkaSBUZXN0MQswCQYDVQQGEwJGUjAgFw0yNjA5
        MjEyMDMxMzlaGA8yMTI2MDgyODIwMzEzOVowPjEaMBgGA1UEAwwRaGVpZGkgbXRs
        cyBjbGllbnQxEzARBgNVBAoMCkhlaWRpIFRlc3QxCzAJBgNVBAYTAkZSMFkwEwYH
        KoZIzj0CAQYIKoZIzj0DAQcDQgAEyL/VRHTs0CgXrQWcBfg3HKDLCuR2lCSVtKM0
        9GcBviq2s2Utd9Jioe1/kvOkbPVoTTQxXlyZHrEt1i5BBjFYBaOBszCBsDBgBgNV
        HREEWTBXghJjbGllbnQuZXhhbXBsZS5jb22GI2h0dHBzOi8vY2xpZW50LmV4YW1w
        bGUuY29tL2NhbGxiYWNrhwTGM2QHgRZvcHNAY2xpZW50LmV4YW1wbGUuY29tMAwG
        A1UdEwEB/wQCMAAwHQYDVR0OBBYEFEyUIsZkQTWEyTlA2awgRVYQBqxhMB8GA1Ud
        IwQYMBaAFL0dVm8T+DfqZlIl08qly1D3okZ/MAoGCCqGSM49BAMCA0cAMEQCIAUe
        iMoZGoDHFZm1UfK8vYOlNxNyqu0ODMdOWYAaOx8zAiBbs0adJhJ1JF+oYPE6CM/L
        mxDM7hva3XOginrDAsObLw==
        -----END CERTIFICATE-----
        PEM;

    private const string OTHER_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB3TCCAYOgAwIBAgIBAjAKBggqhkjOPQQDAjA6MRYwFAYDVQQDDA1IZWlkaSBU
        ZXN0IENBMRMwEQYDVQQKDApIZWlkaSBUZXN0MQswCQYDVQQGEwJGUjAgFw0yNjA5
        MjEyMDMxNTNaGA8yMTI2MDgyODIwMzE1M1owRDEgMB4GA1UEAwwXaGVpZGkgbXRs
        cyBvdGhlciBjbGllbnQxEzARBgNVBAoMCkhlaWRpIFRlc3QxCzAJBgNVBAYTAkZS
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH6+CxCGnrzCua4SWMfr4KzpFXVHH
        /4NL2xuTK06roxIWx3GwR6bsCiITZxMbb5KIbc4vup2pih005KWKnBu8GKNuMGww
        HAYDVR0RBBUwE4IRb3RoZXIuZXhhbXBsZS5jb20wDAYDVR0TAQH/BAIwADAdBgNV
        HQ4EFgQUBq1+W89kzuHZUDHrxwC40am0570wHwYDVR0jBBgwFoAUvR1WbxP4N+pm
        UiXTyqXLUPeiRn8wCgYIKoZIzj0EAwIDSAAwRQIgbcUYrF9lY6AY2Pa0we6KYPNf
        B+tfY0pXUcKwnsidhsoCIQCmyxDDvncfJ7k2bDmLWqTvnBl1ykTZiwiKBH2nC3Og
        Ag==
        -----END CERTIFICATE-----
        PEM;

    private const string SELF_SIGNED_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICADCCAaagAwIBAgIBAzAKBggqhkjOPQQDAjA+MRowGAYDVQQDDBFoZWlkaSBt
        dGxzIGNsaWVudDETMBEGA1UECgwKSGVpZGkgVGVzdDELMAkGA1UEBhMCRlIwIBcN
        MjYwOTIxMjAzMTM5WhgPMjEyNjA4MjgyMDMxMzlaMD4xGjAYBgNVBAMMEWhlaWRp
        IG10bHMgY2xpZW50MRMwEQYDVQQKDApIZWlkaSBUZXN0MQswCQYDVQQGEwJGUjBZ
        MBMGByqGSM49AgEGCCqGSM49AwEHA0IABMnrmMNkWzMcMjv2L+6YQ5jg7QrmF5WR
        3YrUH6qcd0kOi1QjWBXiGAppbfl8d7C4V6q6b86d3afhicRoVfu2AD+jgZIwgY8w
        YAYDVR0RBFkwV4ISY2xpZW50LmV4YW1wbGUuY29thiNodHRwczovL2NsaWVudC5l
        eGFtcGxlLmNvbS9jYWxsYmFja4cExjNkB4EWb3BzQGNsaWVudC5leGFtcGxlLmNv
        bTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQ+C12XDIr1Gs4nrv6P5WzribaOnDAK
        BggqhkjOPQQDAgNIADBFAiEArZvGJgZbp4cOdeYh7REEo43eNvG5cHFFDmJHpK8U
        n4ACIDRIaOS7f2MbuFsLYYMF3Se1aM3AzdpPUKc50N7sQJYf
        -----END CERTIFICATE-----
        PEM;

    private const string REISSUED_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICADCCAaagAwIBAgIBBDAKBggqhkjOPQQDAjA+MRowGAYDVQQDDBFoZWlkaSBt
        dGxzIGNsaWVudDETMBEGA1UECgwKSGVpZGkgVGVzdDELMAkGA1UEBhMCRlIwIBcN
        MjYwOTIxMjAzMTM5WhgPMjEyNjA4MjgyMDMxMzlaMD4xGjAYBgNVBAMMEWhlaWRp
        IG10bHMgY2xpZW50MRMwEQYDVQQKDApIZWlkaSBUZXN0MQswCQYDVQQGEwJGUjBZ
        MBMGByqGSM49AgEGCCqGSM49AwEHA0IABH8iRkRP2qF/HhCAL/mvIt6KDX8H0j2G
        Vbib/qv1Hmx8knpRu3hn1Q9irNuAI1/QrTtsq8pgIfXK3TG5T42PVE6jgZIwgY8w
        YAYDVR0RBFkwV4ISY2xpZW50LmV4YW1wbGUuY29thiNodHRwczovL2NsaWVudC5l
        eGFtcGxlLmNvbS9jYWxsYmFja4cExjNkB4EWb3BzQGNsaWVudC5leGFtcGxlLmNv
        bTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBR3MBMfuj9jB7eZsd6Dn27lhUBO/DAK
        BggqhkjOPQQDAgNIADBFAiEAzlxoBFi71b9yyHd3pfV/ja0s9In8iT5UCK9Ahv+u
        ihwCIAIq7kbrmqIHNHbk4wQah0/N/9ovXu3VKpI8momYnaoI
        -----END CERTIFICATE-----
        PEM;

    /**
     * The subject distinguished name of "client" and of "selfSigned", as openssl writes it
     * ("openssl x509 -noout -subject -nameopt RFC2253"). A registration is normalised by the reader of
     * the provider, so what is registered is the name as the tool that printed it wrote it.
     */
    public const string SUBJECT_DN = 'C=FR,O=Heidi Test,CN=heidi mtls client';

    public const string DNS_NAME = 'client.example.com';

    public const string URI = 'https://client.example.com/callback';

    public const string IP_ADDRESS = '198.51.100.7';

    public const string EMAIL_ADDRESS = 'ops@client.example.com';

    public static function client(): ClientCertificate
    {
        return self::of(self::CLIENT_PEM);
    }

    public static function other(): ClientCertificate
    {
        return self::of(self::OTHER_PEM);
    }

    public static function selfSigned(): ClientCertificate
    {
        return self::of(self::SELF_SIGNED_PEM);
    }

    public static function reissued(): ClientCertificate
    {
        return self::of(self::REISSUED_PEM);
    }

    /**
     * A certificate as a client publishes it (RFC 7517 §4.7, RFC 8705 §2.2): the JWK of its public key
     * is not read by this provider, the "x5c" is, so the set below is the smallest one a client can
     * publish to authenticate with a certificate.
     */
    public static function publishedIn(ClientCertificate $certificate): ClientJwks
    {
        return new ClientJwks([[
            'kty' => 'EC',
            'crv' => 'P-256',
            'x5c' => [self::base64($certificate)],
        ]]);
    }

    /**
     * The same set, naming the certificate by its thumbprint instead of carrying it (RFC 7517 §4.9).
     */
    public static function thumbprintedIn(ClientCertificate $certificate): ClientJwks
    {
        return new ClientJwks([[
            'kty' => 'EC',
            'crv' => 'P-256',
            'x5t#S256' => $certificate->x5tS256(),
        ]]);
    }

    /**
     * What the edge hands over, envelope included (architecture §6).
     */
    public static function pemOf(ClientCertificate $certificate): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . self::base64($certificate) . "\n-----END CERTIFICATE-----\n";
    }

    private static function base64(ClientCertificate $certificate): string
    {
        return base64_encode($certificate->der);
    }

    private static function of(string $pem): ClientCertificate
    {
        return ClientCertificate::fromPem($pem) ?? throw new LogicException('A fixture carries a certificate.');
    }
}
