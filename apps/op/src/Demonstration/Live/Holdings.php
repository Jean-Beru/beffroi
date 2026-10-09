<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

use function is_string;

/**
 * The names a run holds what it was answered under, which are the names the protocol gives them: the
 * code a device flow polls on (RFC 8628 §3.2), the identifier a backchannel flow polls on (CIBA Core
 * §7.3), the tokens every flow ends with (RFC 6749 §5.1). Written once, because the hop that keeps one
 * and the hop that spends it are two classes.
 */
final readonly class Holdings
{
    public const string DEVICE_CODE = 'device_code';

    public const string USER_CODE = 'user_code';

    public const string VERIFICATION_URI = 'verification_uri_complete';

    public const string AUTH_REQUEST_ID = 'auth_req_id';

    public const string ACCESS_TOKEN = 'access_token';

    public const string REFRESH_TOKEN = 'refresh_token';

    /**
     * @param array<array-key, mixed> $answer
     * @param list<string>            $names
     *
     * @return array<string, string> the values of those names the answer carried, and no other
     */
    public static function kept(array $answer, array $names): array
    {
        $kept = [];
        foreach ($names as $name) {
            $value = $answer[$name] ?? null;
            if (is_string($value) && $value !== '') {
                $kept[$name] = $value;
            }
        }

        return $kept;
    }
}
