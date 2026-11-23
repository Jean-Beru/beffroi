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
    public const string AUTHORITY_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB5DCCAYmgAwIBAgIUOlKbbBAL9UuWFNxqOPg+GaM4IsswCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQmVmZnJvaSBUZXN0IENBMRUwEwYDVQQKDAxCZWZmcm9pIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAw
        WjA+MRgwFgYDVQQDDA9CZWZmcm9pIFRlc3QgQ0ExFTATBgNVBAoMDEJlZmZyb2kg
        VGVzdDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARw+oqQ
        lP2Ni9/oKFiDYZgKhAQhKyPrwP85b2dSnkxYYaWsxZda0pLPecMzTVQMpF4qO03V
        cokAdMX9D4eMM9YSo2MwYTAdBgNVHQ4EFgQUrZANWy2Io/0O1w5YOoypxWj0sm4w
        HwYDVR0jBBgwFoAUrZANWy2Io/0O1w5YOoypxWj0sm4wDwYDVR0TAQH/BAUwAwEB
        /zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhAKdLI1+PA7svuZD/
        EtLvor9AAt+LQ+ESbKDn622WfdY4AiEAi0v8QYIGA3Jci2Gy/SxzXYUwl7+hRObr
        qTPfpNP02qw=
        -----END CERTIFICATE-----
        PEM;

    public const string ANOTHER_AUTHORITY_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB4zCCAYmgAwIBAgIUYznMDwpC5HEd+yb3/dkAEGhaGpQwCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQW5vdGhlciBUZXN0IENBMRUwEwYDVQQKDAxBbm90aGVyIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAw
        WjA+MRgwFgYDVQQDDA9Bbm90aGVyIFRlc3QgQ0ExFTATBgNVBAoMDEFub3RoZXIg
        VGVzdDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQoyqpf
        383tV0SJLK8ZmH9KBuv1z21QMeJcAh/X21lpTJFRBJSrBKreKU4YPrpimt4CxhLr
        FGe6L6jJm/thwaJNo2MwYTAdBgNVHQ4EFgQUU6bv1MkmzcauSjh4aNyFN+a2nf0w
        HwYDVR0jBBgwFoAUU6bv1MkmzcauSjh4aNyFN+a2nf0wDwYDVR0TAQH/BAUwAwEB
        /zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgMMtEdd5+W3mXrnS4
        +CI7SepaZpSMLcqIYYCJdEK5cRICIQClYvoTiAt/nel4OId7vjWVvaGw37bQlALB
        soKUAohaHw==
        -----END CERTIFICATE-----
        PEM;

    private const string CLIENT_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICOTCCAd6gAwIBAgIUEUbHDO5ZalqeUe7YjgexPXUOoWYwCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQmVmZnJvaSBUZXN0IENBMRUwEwYDVQQKDAxCZWZmcm9pIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAw
        WjBCMRwwGgYDVQQDDBNiZWZmcm9pIG10bHMgY2xpZW50MRUwEwYDVQQKDAxCZWZm
        cm9pIFRlc3QxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        HVaix5t0Q8yDYtsvNtQc1JXB7Sg5imB3nQzN9DPYPJMWUFCK13jWmQNPThRR26R4
        Xy0BsJlze2mLOS4QvGCkVKOBszCBsDBgBgNVHREEWTBXghJjbGllbnQuZXhhbXBs
        ZS5jb22GI2h0dHBzOi8vY2xpZW50LmV4YW1wbGUuY29tL2NhbGxiYWNrhwTGM2QH
        gRZvcHNAY2xpZW50LmV4YW1wbGUuY29tMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
        FE19P6JVBT53uOuabQWLVJ4+P3DqMB8GA1UdIwQYMBaAFK2QDVstiKP9DtcOWDqM
        qcVo9LJuMAoGCCqGSM49BAMCA0kAMEYCIQCXlEN2gH4+x42qByXW4tSR4zfkYNbV
        zOqsdLE3LrtHvAIhALXKHERJoecU4hnO1aQw0K77A2rVilKHdHRV0rfIVDn9
        -----END CERTIFICATE-----
        PEM;

    private const string OTHER_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIIB+TCCAZ6gAwIBAgIURaYl0l1rvT9F/aLcw1axqHLE4QgwCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQmVmZnJvaSBUZXN0IENBMRUwEwYDVQQKDAxCZWZmcm9pIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAw
        WjBIMSIwIAYDVQQDDBliZWZmcm9pIG10bHMgb3RoZXIgY2xpZW50MRUwEwYDVQQK
        DAxCZWZmcm9pIFRlc3QxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0D
        AQcDQgAEk2eVaDdDr/QSMD5NuXMsNdNhpBCc8JhqlpIQg9JydvODJCkz8yEPYKU0
        3gqREewD9OoMjDSdcb58y434wJTTQ6NuMGwwHAYDVR0RBBUwE4IRb3RoZXIuZXhh
        bXBsZS5jb20wDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUAEKKatcgvKSxadl5QLZ4
        J+xkgdwwHwYDVR0jBBgwFoAUrZANWy2Io/0O1w5YOoypxWj0sm4wCgYIKoZIzj0E
        AwIDSQAwRgIhAMIeQjfHucNOksp1TUnAqrNlJffhbpRg+AlkJ9wLC0RIAiEAyWFY
        D5f4l2nYUynI5zxBHkqg780JLwdusVwI3thFobk=
        -----END CERTIFICATE-----
        PEM;

    private const string OF_ANOTHER_AUTHORITY_PEM = <<<'PEM'
        -----BEGIN CERTIFICATE-----
        MIICODCCAd6gAwIBAgIUMuajmg+azHizZ2vJ7KgN7OWcookwCgYIKoZIzj0EAwIw
        PjEYMBYGA1UEAwwPQW5vdGhlciBUZXN0IENBMRUwEwYDVQQKDAxBbm90aGVyIFRl
        c3QxCzAJBgNVBAYTAkZSMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjYwMTAxMDAwMDAw
        WjBCMRwwGgYDVQQDDBNiZWZmcm9pIG10bHMgY2xpZW50MRUwEwYDVQQKDAxCZWZm
        cm9pIFRlc3QxCzAJBgNVBAYTAkZSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        HVaix5t0Q8yDYtsvNtQc1JXB7Sg5imB3nQzN9DPYPJMWUFCK13jWmQNPThRR26R4
        Xy0BsJlze2mLOS4QvGCkVKOBszCBsDBgBgNVHREEWTBXghJjbGllbnQuZXhhbXBs
        ZS5jb22GI2h0dHBzOi8vY2xpZW50LmV4YW1wbGUuY29tL2NhbGxiYWNrhwTGM2QH
        gRZvcHNAY2xpZW50LmV4YW1wbGUuY29tMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE
        FE19P6JVBT53uOuabQWLVJ4+P3DqMB8GA1UdIwQYMBaAFFOm79TJJs3Grko4eGjc
        hTfmtp39MAoGCCqGSM49BAMCA0gAMEUCIQDj29Eq9+LfDKC3+D2MZhO37Bv1O6ad
        x/keqmoaMHdqPAIgdg1ubsoJ+LtPvT4ZODaYZNnepKZl1xFt3SDQ9+aKP9Y=
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

    /**
     * The names of client(), issued by the authority of ANOTHER_AUTHORITY_PEM.
     */
    public static function ofAnotherAuthority(): ClientCertificate
    {
        return self::of(self::OF_ANOTHER_AUTHORITY_PEM);
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
