<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function base64_encode;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use LogicException;

/**
 * RFC 8705 §2
 */
final class Certificates
{
    private const string CLIENT_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICNzCCAd6gAwIBAgIUZCRlYKl43G0AyCgRWbCflF0+vAEwCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQmVmZnJvaSBUZXN0IENBMRUwEwYDVQQKDAxCZWZmcm9pIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTI2MTAwMjIxMzgyNloYDzIxMjYwOTA4MjEzODI2
        WjBCMRwwGgYDVQQDDBNiZWZmcm9pIG10bHMgY2xpZW50MRUwEwYDVQQKDAxCZWZm
        cm9pIFRlc3QxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        HVaix5t0Q8yDYtsvNtQc1JXB7Sg5imB3nQzN9DPYPJMWUFCK13jWmQNPThRR26R4
        Xy0BsJlze2mLOS4QvGCkVKOBszCBsDBgBgNVHREEWTBXghJjbGllbnQuZXhhbXBs
        ZS5jb22GI2h0dHBzOi8vY2xpZW50LmV4YW1wbGUuY29tL2NhbGxiYWNrhwTGM2QH
        gRZvcHNAY2xpZW50LmV4YW1wbGUuY29tMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
        FE19P6JVBT53uOuabQWLVJ4+P3DqMB8GA1UdIwQYMBaAFLtKzbYMIV/QstRhuatL
        u1jESycyMAoGCCqGSM49BAMCA0cAMEQCIBUFVEdsivRmuyHRKpWBKjhWLpZqIvop
        W8Jz1NSNS63zAiAg5U9dmbSR6/msXxqyl45LaCRF6XMSvvh/IwgwuordhQ==
        -----END CERTIFICATE-----
        PEM;

    private const string OTHER_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB+DCCAZ6gAwIBAgIUDGgirj9ommtYT0aNPFNsweYyse4wCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQmVmZnJvaSBUZXN0IENBMRUwEwYDVQQKDAxCZWZmcm9pIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTI2MTAwMjIxMzgyNloYDzIxMjYwOTA4MjEzODI2
        WjBIMSIwIAYDVQQDDBliZWZmcm9pIG10bHMgb3RoZXIgY2xpZW50MRUwEwYDVQQK
        DAxCZWZmcm9pIFRlc3QxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0D
        AQcDQgAEk2eVaDdDr/QSMD5NuXMsNdNhpBCc8JhqlpIQg9JydvODJCkz8yEPYKU0
        3gqREewD9OoMjDSdcb58y434wJTTQ6NuMGwwHAYDVR0RBBUwE4IRb3RoZXIuZXhh
        bXBsZS5jb20wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUAEKKatcgvKSxadl5QLZ4
        J+xkgdwwHwYDVR0jBBgwFoAUu0rNtgwhX9Cy1GG5q0u7WMRLJzIwCgYIKoZIzj0E
        AwIDSAAwRQIgbDrwfI+9+4S4Y0cROO6eWbkTuCbsXL1hfDMah3iGAE8CIQCuj71r
        /3hlg5NLJF5DoDGIagf1J0xwFve7/bsxyIRWWA==
        -----END CERTIFICATE-----
        PEM;

    private const string SELF_SIGNED_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICGjCCAcGgAwIBAgIUWYn5MWZyn3gTZukk8cAJuCVwmQkwCgYIKoZIzj0EAwIw
        QjEcMBoGA1UEAwwTYmVmZnJvaSBtdGxzIGNsaWVudDEVMBMGA1UECgwMQmVmZnJv
        aSBUZXN0MQswCQYDVQQGEwJGUjAgFw0yNjEwMDIyMTM4MjZaGA8yMTI2MDkwODIx
        MzgyNlowQjEcMBoGA1UEAwwTYmVmZnJvaSBtdGxzIGNsaWVudDEVMBMGA1UECgwM
        QmVmZnJvaSBUZXN0MQswCQYDVQQGEwJGUjBZMBMGByqGSM49AgEGCCqGSM49AwEH
        A0IABB1WosebdEPMg2LbLzbUHNSVwe0oOYpgd50MzfQz2DyTFlBQitd41pkDT04U
        UdukeF8tAbCZc3tpizkuELxgpFSjgZIwgY8wYAYDVR0RBFkwV4ISY2xpZW50LmV4
        YW1wbGUuY29thiNodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYWxsYmFja4cE
        xjNkB4EWb3BzQGNsaWVudC5leGFtcGxlLmNvbTAMBgNVHRMBAf8EAjAAMB0GA1Ud
        DgQWBBRNfT+iVQU+d7jrmm0Fi1SePj9w6jAKBggqhkjOPQQDAgNHADBEAiBOU6bQ
        odXsqgQaOYY47mehA9tWmwwcJeZAcsnY5C1+iAIgH4/LsQYgrSU4pENyGX3eVto0
        elf03h4ecHU/lOAAv0I=
        -----END CERTIFICATE-----
        PEM;

    private const string REISSUED_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICGjCCAcGgAwIBAgIUbh1J8t1uMaDM+6eQdgpAUbF778YwCgYIKoZIzj0EAwIw
        QjEcMBoGA1UEAwwTYmVmZnJvaSBtdGxzIGNsaWVudDEVMBMGA1UECgwMQmVmZnJv
        aSBUZXN0MQswCQYDVQQGEwJGUjAgFw0yNjEwMDIyMTM4MjZaGA8yMTI2MDkwODIx
        MzgyNlowQjEcMBoGA1UEAwwTYmVmZnJvaSBtdGxzIGNsaWVudDEVMBMGA1UECgwM
        QmVmZnJvaSBUZXN0MQswCQYDVQQGEwJGUjBZMBMGByqGSM49AgEGCCqGSM49AwEH
        A0IABEHIbI2KwKsRzZqHcGjVIFgkKDgrOstkzxoE4653IBnAYLUC4TE9iSnW8gRb
        YQCCev5BbSXn0nUjxpndv7/WmYijgZIwgY8wYAYDVR0RBFkwV4ISY2xpZW50LmV4
        YW1wbGUuY29thiNodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYWxsYmFja4cE
        xjNkB4EWb3BzQGNsaWVudC5leGFtcGxlLmNvbTAMBgNVHRMBAf8EAjAAMB0GA1Ud
        DgQWBBS3NbZhSnhemhetx+0r/T3filZ00jAKBggqhkjOPQQDAgNHADBEAiBh5KL/
        oPoElvYiq2+zPCgGkrmSo345s1SqUVgN3EjSmwIgAiM1cN4pGezwV2kG0ptstwS0
        zVMisBWDviEIUWzaBoM=
        -----END CERTIFICATE-----
        PEM;

    public const string SUBJECT_DN = 'C=FR,O=Beffroi Test,CN=beffroi mtls client';

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
     * RFC 7517 §4.7, RFC 8705 §2.2
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
     * RFC 7517 §4.9
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
     * Architecture §6
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
