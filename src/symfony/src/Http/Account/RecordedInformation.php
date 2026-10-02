<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use function array_filter;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\User;
use function implode;

/**
 * What this provider holds about a person, read once for the two places that read it (architecture §5.2):
 * the page where they consult it, and the home of the account, which says how much of it there is. The
 * fields are enumerated here and nowhere else, so that a claim the core learns to hold appears on the page
 * and in the count by one line added.
 *
 * Two readings, because the two halves answer different questions. Keeping an account for someone keeps a
 * name to sign in with, an identifier every client receives (OIDC Core §2) and two dates, whatever the
 * person told us; what they told us is the rest, each one only when it is set, since a detail nobody gave
 * is not a line of a page.
 */
final readonly class RecordedInformation
{
    /**
     * @return list<RecordedDetail>
     */
    public static function identityOf(User $user): array
    {
        return [
            RecordedDetail::said('username', $user->username),
            RecordedDetail::said('subject', $user->subject->value),
            RecordedDetail::dated('created_at', $user->createdAt),
            RecordedDetail::dated('updated_at', $user->updatedAt),
        ];
    }

    /**
     * The contact details with their verification and the standard claims of OIDC Core §5.1, in the order
     * a client asks for them.
     *
     * @return list<RecordedDetail>
     */
    public static function claimsOf(User $user): array
    {
        $details = [];
        if ($user->email !== null) {
            $details[] = RecordedDetail::verifiable('email', $user->email->value, $user->emailVerified);
        }
        if ($user->phoneNumber !== null) {
            $details[] = RecordedDetail::verifiable('phone_number', $user->phoneNumber, $user->phoneNumberVerified);
        }
        $profile = $user->profile;
        $claims = [
            'name' => $profile->name,
            'given_name' => $profile->givenName,
            'family_name' => $profile->familyName,
            'middle_name' => $profile->middleName,
            'nickname' => $profile->nickname,
            'preferred_username' => $profile->preferredUsername,
            'birthdate' => $profile->birthdate,
            'gender' => $profile->gender,
            'locale' => $profile->locale,
            'zoneinfo' => $profile->zoneinfo,
            'profile_url' => $profile->profileUrl,
            'picture_url' => $profile->pictureUrl,
            'website_url' => $profile->websiteUrl,
            'address' => self::address($user->address),
        ];
        foreach ($claims as $key => $value) {
            if ($value !== null) {
                $details[] = RecordedDetail::said($key, $value);
            }
        }

        return $details;
    }

    /**
     * The address in one line: the one the person gave formatted if they gave one (OIDC Core §5.1.1), its
     * parts joined otherwise. An address with no part at all is no address, which the core holds as none.
     */
    private static function address(?Address $address): ?string
    {
        if ($address === null) {
            return null;
        }
        if ($address->formatted !== null) {
            return $address->formatted;
        }
        $parts = array_filter(
            [$address->streetAddress, $address->postalCode, $address->locality, $address->region, $address->country],
            static fn (?string $part): bool => $part !== null,
        );

        return $parts === [] ? null : implode(', ', $parts);
    }
}
