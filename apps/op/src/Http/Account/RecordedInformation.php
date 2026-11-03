<?php

declare(strict_types=1);

namespace App\Http\Account;

use function array_filter;
use function array_values;
use Beffroi\Core\Domain\Identity\Address;
use Beffroi\Core\Domain\Identity\User;
use function implode;

/**
 * What this provider holds about a person, read once for the two places that read it (architecture §5.2):
 * the page where they consult it, and the home of the account, which says how much of it there is. The
 * fields are enumerated here and nowhere else, so that a claim the core learns to hold appears on the page
 * and in the count by one line added. **A key here is the name the claim gives itself** (OIDC Core §5.1,
 * `ClaimInterface::name()`), because what the tenant opens is offered in the line of the claim it is about:
 * a key of this list that no claim answers is a line nobody could ever change.
 *
 * Two readings, because the two halves answer different questions. Keeping an account for someone keeps a
 * name to sign in with and two dates, whatever the person told us; what they told us is the rest.
 *
 * The identifier a client receives is on neither: it is the `sub` of a token and not a thing a person came
 * to read of themselves, and a client of a sector that asks for a pairwise one receives another identifier
 * altogether (OIDC Core §8.1), so a page that named this one would be telling them something false.
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
            RecordedDetail::dated('created_at', $user->createdAt),
            RecordedDetail::dated('updated_at', $user->updatedAt),
        ];
    }

    /**
     * What this provider holds of that person: the contact details with their verification and the standard
     * claims of OIDC Core §5.1, in the order a client asks for them, each only when it is set. What the
     * home of the account counts.
     *
     * @return list<RecordedDetail>
     */
    public static function claimsOf(User $user): array
    {
        return array_values(array_filter(
            self::everyClaimOf($user),
            static fn (RecordedDetail $detail): bool => $detail->value !== null,
        ));
    }

    /**
     * Every claim this provider can hold of that person, in the same order, the ones it holds nothing of
     * included: the page where somebody reads their record is the page where they correct it, so a claim
     * they may fill in is a line of it before they have filled it.
     *
     * @return list<RecordedDetail>
     */
    public static function everyClaimOf(User $user): array
    {
        $details = [];
        $details[] = $user->email === null
            ? RecordedDetail::nothing('email')
            : RecordedDetail::verifiable('email', $user->email->value, $user->emailVerified);
        $details[] = $user->phoneNumber === null
            ? RecordedDetail::nothing('phone_number')
            : RecordedDetail::verifiable('phone_number', $user->phoneNumber, $user->phoneNumberVerified);
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
            'profile' => $profile->profileUrl,
            'picture' => $profile->pictureUrl,
            'website' => $profile->websiteUrl,
            'address' => self::address($user->address),
        ];
        foreach ($claims as $key => $value) {
            $details[] = $value === null ? RecordedDetail::nothing($key) : RecordedDetail::said($key, $value);
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
