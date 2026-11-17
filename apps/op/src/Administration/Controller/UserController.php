<?php

declare(strict_types=1);

namespace App\Administration\Controller;

use App\Administration\AdministrationAnswer;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Credential\AuthenticatorModels;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\ModelDeclaringCredentialInterface;
use Beffroi\Core\Domain\Credential\RevocableCredentialInterface;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Application\Administration\AdministeredPerson;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use function array_filter;
use function array_map;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * A person of the tenant, by their username: the account and the source that created it, the standard claims it holds
 * (OIDC Core §5.1), the credentials with their kind, name, authenticator and dates, and the groups with the source of
 * each membership, what `beffroi:user:show` prints (decision 0038). Reading them is an act of theirs that names the
 * administrator (`AdministeredPerson`).
 */
#[AsController]
final readonly class UserController
{
    public function __construct(
        private AdministeredPerson $persons,
        private RequestContextFactory $contexts,
        private AuthenticatorModels $models,
    ) {
    }

    #[Route('/users', name: 'beffroi_administration_user', methods: ['GET'])]
    public function __invoke(ActingAdministrator $administrator, Request $request): Response
    {
        $username = $request->query->all()['username'] ?? null;
        if (! is_string($username) || $username === '') {
            return AdministrationAnswer::refusal(Response::HTTP_BAD_REQUEST, 'invalid_request', 'A person is asked for by the "username" of the query, once.');
        }
        $read = $this->persons->named($administrator, $username, $this->contexts->fromRequest($request));
        if ($read === null) {
            return AdministrationAnswer::refusal(Response::HTTP_NOT_FOUND, 'not_found', 'Nobody of the tenant has this username.');
        }
        $user = $read->user;

        return AdministrationAnswer::of([
            'id' => $user->id->toRfc4122(),
            'subject' => $user->subject->value,
            'username' => $user->username,
            'enabled' => $user->isEnabled(),
            'disabled_at' => AdministrationAnswer::moment($user->disabledAt),
            'source' => $user->source->provider ?? 'local',
            'created_at' => AdministrationAnswer::moment($user->createdAt),
            'claims' => (object) self::claims($user),
            'groups' => array_map(static fn (GroupMembership $membership): array => [
                'name' => $membership->group->name,
                'source' => $membership->source->value,
                'added_at' => AdministrationAnswer::moment($membership->addedAt),
            ], $read->memberships),
            'credentials' => array_map(fn (Credential $credential): array => [
                'id' => $credential->id->toRfc4122(),
                'kind' => $credential->kind(),
                'name' => $credential->label(),
                'authenticator' => $credential instanceof ModelDeclaringCredentialInterface ? $this->models->of($credential)?->name : null,
                'created_at' => AdministrationAnswer::moment($credential->createdAt),
                'last_used_at' => AdministrationAnswer::moment($credential->lastUsedAt),
                'revocable' => $credential instanceof RevocableCredentialInterface,
                'revoked_at' => $credential instanceof RevocableCredentialInterface ? AdministrationAnswer::moment($credential->revokedAt) : null,
            ], $read->credentials),
        ]);
    }

    /**
     * The standard claims of OIDC Core §5.1 the account holds, by their names there, and none it does not.
     *
     * @return array<string, mixed>
     */
    private static function claims(User $user): array
    {
        $address = $user->address;

        return array_filter(
            [
                'name' => $user->profile->name,
                'given_name' => $user->profile->givenName,
                'family_name' => $user->profile->familyName,
                'email' => $user->email === null ? null : (string) $user->email,
                'email_verified' => $user->email === null ? null : $user->emailVerified,
                'phone_number' => $user->phoneNumber,
                'phone_number_verified' => $user->phoneNumber === null ? null : $user->phoneNumberVerified,
                'address' => $address === null
                    ? null
                    : array_filter(
                        [
                            'street_address' => $address->streetAddress,
                            'postal_code' => $address->postalCode,
                            'locality' => $address->locality,
                            'region' => $address->region,
                            'country' => $address->country,
                        ],
                        static fn (?string $member): bool => $member !== null,
                    ),
            ],
            static fn (mixed $claim): bool => $claim !== null,
        );
    }
}
