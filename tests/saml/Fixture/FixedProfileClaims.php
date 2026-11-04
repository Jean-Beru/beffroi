<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Saml\Port\ProfileClaimsInterface;

/**
 * spec/saml.md S-45, OIDC Core §5.1
 */
final readonly class FixedProfileClaims implements ProfileClaimsInterface
{
    public const array WIRED = [
        'name',
        'given_name',
        'family_name',
        'middle_name',
        'nickname',
        'preferred_username',
        'birthdate',
        'gender',
        'locale',
        'zoneinfo',
        'profile',
        'picture',
        'website',
        'phone_number',
    ];

    /**
     * @param list<string> $names
     */
    public function __construct(
        private array $names = self::WIRED,
    ) {
    }

    public function names(): array
    {
        return $this->names;
    }
}
