<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

/**
 * The PEM documents an administrator of the tenant of the suite, op.test, gives to set its S/MIME key: the
 * certificates "op.test Test CA" issued for no-reply@op.test.
 */
final class TenantMailSigningKeys
{
    /**
     * @param string $name "op-sender", "op-sender-next" or "op-sender-expired"
     *
     * @return array{private_key: string, certificates: string}
     */
    public static function asked(string $name = 'op-sender', ?string $certificateOf = null): array
    {
        return [
            'private_key' => MailFixtures::read($name . '-key.pem'),
            'certificates' => MailFixtures::read(($certificateOf ?? $name) . '-certificate.pem') . MailFixtures::read('op-ca-certificate.pem'),
        ];
    }
}
