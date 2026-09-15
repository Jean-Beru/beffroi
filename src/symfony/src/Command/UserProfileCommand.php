<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use function array_filter;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Core\Application\Identity\UserProvisioner;
use Heidi\Core\Domain\Identity\Address;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Port\UserRepositoryInterface;
use function implode;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use function trim;

/**
 * The description of a user (architecture §5.5): the standard claims of OIDC Core §5.1 that the "profile",
 * "phone" and "address" scopes stand for, under the names of the specification. The command says the
 * whole description every time: an attribute it does not name is cleared, so that a script provisioning
 * a user is replayable and its result readable from the command line alone. The email address stays
 * with "heidi:user:create".
 */
#[AsCommand(
    name: 'heidi:user:profile',
    description: 'Describe a user with the standard claims of OIDC Core section 5.1; what is not said is cleared.',
)]
final readonly class UserProfileCommand
{
    public function __construct(
        private TenantProvider $tenants,
        private UserRepositoryInterface $users,
        private UserProvisioner $provisioner,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user.')]
        string $username,
        #[Option(description: 'Full name ("name").')]
        ?string $name = null,
        #[Option(description: 'Given name or first name ("given_name").')]
        ?string $givenName = null,
        #[Option(description: 'Surname or last name ("family_name").')]
        ?string $familyName = null,
        #[Option(description: 'Middle name ("middle_name").')]
        ?string $middleName = null,
        #[Option(description: 'Casual name ("nickname").')]
        ?string $nickname = null,
        #[Option(description: 'Shorthand name the user wishes to be referred to by ("preferred_username").')]
        ?string $preferredUsername = null,
        #[Option(description: 'URL of the profile page of the user ("profile"; "--profile" is an option of the console itself).')]
        ?string $profileUrl = null,
        #[Option(description: 'URL of the profile picture of the user ("picture").')]
        ?string $picture = null,
        #[Option(description: 'URL of the web page or blog of the user ("website").')]
        ?string $website = null,
        #[Option(description: 'Gender, "female", "male" or another value ("gender").')]
        ?string $gender = null,
        #[Option(description: 'Birthday, "YYYY-MM-DD" or "YYYY", "0000" for a year the user withholds ("birthdate").')]
        ?string $birthdate = null,
        #[Option(description: 'Time zone of the user, an IANA name such as "Europe/Paris" ("zoneinfo").')]
        ?string $zoneinfo = null,
        #[Option(description: 'Locale of the user, a BCP 47 tag such as "fr-FR" ("locale").')]
        ?string $locale = null,
        #[Option(description: 'Telephone number, E.164 recommended ("phone_number").')]
        ?string $phoneNumber = null,
        #[Option(description: 'The phone number was verified by whoever provisions the user ("phone_number_verified").')]
        bool $phoneNumberVerified = false,
        #[Option(description: 'Full mailing address, lines separated by "\n" ("address.formatted").')]
        ?string $address = null,
        #[Option(description: 'Street address component, lines separated by "\n" ("address.street_address").')]
        ?string $streetAddress = null,
        #[Option(description: 'City or locality ("address.locality").')]
        ?string $locality = null,
        #[Option(description: 'State, province, prefecture or region ("address.region").')]
        ?string $region = null,
        #[Option(description: 'Zip code or postal code ("address.postal_code").')]
        ?string $postalCode = null,
        #[Option(description: 'Country name ("address.country").')]
        ?string $country = null,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $user = $this->users->findByUsername($tenant, trim($username));
        if ($user === null) {
            $io->error(sprintf('There is no user named "%s" in the tenant "%s".', trim($username), $tenant->slug));

            return Command::FAILURE;
        }

        try {
            $this->provisioner->setProfile(
                $user,
                new Profile(
                    self::given($name),
                    self::given($givenName),
                    self::given($familyName),
                    self::given($middleName),
                    self::given($nickname),
                    self::given($preferredUsername),
                    self::given($profileUrl),
                    self::given($picture),
                    self::given($website),
                    self::given($gender),
                    self::given($birthdate),
                    self::given($zoneinfo),
                    self::given($locale),
                ),
                self::given($phoneNumber),
                $phoneNumberVerified,
                new Address(
                    self::given($address),
                    self::given($streetAddress),
                    self::given($locality),
                    self::given($region),
                    self::given($postalCode),
                    self::given($country),
                ),
            );
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        }

        $io->definitionList(
            [
                'Username' => $user->username,
            ],
            [
                'Name' => $user->profile->name ?? '',
            ],
            [
                'Given name' => $user->profile->givenName ?? '',
            ],
            [
                'Family name' => $user->profile->familyName ?? '',
            ],
            [
                'Phone number' => $user->phoneNumber === null ? '' : sprintf('%s (%s)', $user->phoneNumber, $user->phoneNumberVerified ? 'verified' : 'unverified'),
            ],
            [
                'Address' => $user->address === null ? '' : implode(', ', array_filter([
                    $user->address->streetAddress,
                    $user->address->postalCode,
                    $user->address->locality,
                    $user->address->region,
                    $user->address->country,
                ], static fn (?string $member): bool => $member !== null)),
            ],
        );
        $io->success(sprintf('The user "%s" is described.', $user->username));

        return Command::SUCCESS;
    }

    /**
     * An option given empty says nothing, like an option not given.
     */
    private static function given(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
