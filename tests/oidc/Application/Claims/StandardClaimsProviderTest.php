<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Claims;

use function array_keys;
use function array_map;
use function array_values;
use Heidi\Core\Domain\Identity\Address;
use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Domain\Identity\Profile;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Scope\Scope;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class StandardClaimsProviderTest extends TestCase
{
    private StandardClaimsProvider $provider;

    protected function setUp(): void
    {
        $this->provider = new StandardClaimsProvider();
    }

    /**
     * OIDC Core §5.4: "profile" stands for the fourteen claims of §5.1 about the person, "updated_at"
     * included, as a number of seconds; nothing of the other scopes leaks in.
     */
    #[Test]
    public function theProfileScopeGivesTheProfileClaims(): void
    {
        static::assertSame([
            'name' => 'Alice Martin',
            'given_name' => 'Alice',
            'family_name' => 'Martin',
            'middle_name' => 'Jeanne',
            'nickname' => 'ali',
            'preferred_username' => 'alice',
            'profile' => 'https://social.example/alice',
            'picture' => 'https://social.example/alice.png',
            'website' => 'https://alice.example',
            'gender' => 'female',
            'birthdate' => '1990-04-12',
            'zoneinfo' => 'Europe/Paris',
            'locale' => 'fr-FR',
            'updated_at' => Fixtures::now()->modify('+1 day')->getTimestamp(),
        ], $this->provider->claims(self::fullUser(), self::scopes('profile'), []));
    }

    /**
     * OIDC Core §5.4 "email", "address", "phone"; §5.1: "email_verified" and "phone_number_verified" are
     * JSON booleans, true or false, never strings (architecture §9); §5.1.1: the address is an object
     * with the members that have a value.
     */
    #[Test]
    public function theEmailAddressAndPhoneScopesGiveTheirClaimsWithBooleanFlags(): void
    {
        $claims = $this->provider->claims(self::fullUser(), self::scopes('email', 'address', 'phone'), []);

        static::assertSame([
            'email' => 'alice@acme.example',
            'email_verified' => true,
            'phone_number' => '+33612345678',
            'phone_number_verified' => false,
            'address' => [
                'formatted' => "1 rue de la Paix\n75002 Paris",
                'street_address' => '1 rue de la Paix',
                'locality' => 'Paris',
                'postal_code' => '75002',
                'country' => 'FR',
            ],
        ], $claims);
        static::assertSame('{"email":"alice@acme.example","email_verified":true,"phone_number":"+33612345678","phone_number_verified":false,"address":{"formatted":"1 rue de la Paix\n75002 Paris","street_address":"1 rue de la Paix","locality":"Paris","postal_code":"75002","country":"FR"}}', json_encode($claims, JSON_THROW_ON_ERROR));
    }

    /**
     * OIDC Core §5.3.2: a claim the user has no value for is left out; the verification flag goes with
     * the value it qualifies. A bare user with every scope gives "updated_at" alone.
     */
    #[Test]
    public function absentAttributesGiveNoClaimAndNoFlag(): void
    {
        $user = Fixtures::user();

        static::assertSame([
            'updated_at' => Fixtures::now()->getTimestamp(),
        ], $this->provider->claims($user, self::scopes('profile', 'email', 'address', 'phone'), []));

        $user->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());
        $user->changeAddress(new Address(), Fixtures::now());
        static::assertSame([
            'email' => 'alice@acme.example',
            'email_verified' => false,
        ], $this->provider->claims($user, self::scopes('email', 'address'), []));
    }

    /**
     * OIDC Core §5.4: "openid" asks for no claim of its own ("sub" is the resolver's), and a scope
     * outside the four of §5.4 asks for none either.
     */
    #[Test]
    public function otherScopesGiveNothing(): void
    {
        static::assertSame([], $this->provider->claims(self::fullUser(), self::scopes('openid', 'offline_access', 'api:read'), []));
        static::assertSame([], $this->provider->claims(self::fullUser(), [], []));
    }

    /**
     * OIDC Core §5.5: a claim asked for by name is served without its scope; "essential", "value" and
     * "values" (§5.5.1) change nothing to what is served; a name the provider does not know gives
     * nothing. Requested and scope claims come out once each, in the order of §5.1.
     */
    #[Test]
    public function claimsRequestedByNameAreServedWithoutTheirScope(): void
    {
        $claims = $this->provider->claims(self::fullUser(), self::scopes('email'), [
            'email_verified' => new ClaimRequest(true, false),
            'given_name' => new ClaimRequest(),
            'phone_number' => new ClaimRequest(false, null, ['+33600000000']),
            'groups' => new ClaimRequest(true),
        ]);

        static::assertSame(['given_name', 'email', 'email_verified', 'phone_number'], array_keys($claims));
        static::assertSame('Alice', $claims['given_name']);
        static::assertTrue($claims['email_verified']);
        static::assertSame('+33612345678', $claims['phone_number']);
    }

    /**
     * @return list<Scope>
     */
    private static function scopes(string ...$values): array
    {
        return array_values(array_map(static fn (string $value): Scope => new Scope($value), $values));
    }

    private static function fullUser(): User
    {
        return new User(
            Uuid::v7(),
            Fixtures::tenant(),
            new Subject('alice-subject'),
            'alice',
            new EmailAddress('alice@acme.example'),
            true,
            new Profile('Alice Martin', 'Alice', 'Martin', 'Jeanne', 'ali', 'alice', 'https://social.example/alice', 'https://social.example/alice.png', 'https://alice.example', 'female', '1990-04-12', 'Europe/Paris', 'fr-FR'),
            '+33612345678',
            false,
            new Address("1 rue de la Paix\n75002 Paris", '1 rue de la Paix', 'Paris', null, '75002', 'FR'),
            Fixtures::now(),
            Fixtures::now()->modify('+1 day'),
        );
    }
}
