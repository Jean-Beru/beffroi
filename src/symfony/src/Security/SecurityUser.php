<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Credential\PasswordCredential;
use Heidi\Core\Domain\Identity\User;
use function is_bool;
use function is_string;
use LogicException;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;

/**
 * What the security component of Symfony sees of a user of the core (architecture §5.4, decision 0002):
 * an adapter over the User and its PasswordCredential, never the User of a host application. The
 * firewall reads the identifier, the roles and the hash; the bundle reads the entities behind them to
 * open the session and to rehash the password.
 *
 * The token of the firewall is serialised into the HTTP session between two requests: what is kept is
 * the identifier, the username, the hash and the state, enough to refresh the user through the provider
 * and to tell that a password changed; the entities are read again from the rows, never from the cookie.
 */
final class SecurityUser implements UserInterface, PasswordAuthenticatedUserInterface, EquatableInterface
{
    public const string ROLE = 'ROLE_USER';

    public readonly Uuid $id;

    /**
     * @var non-empty-string
     */
    public readonly string $username;

    public readonly bool $enabled;

    private readonly ?string $password;

    private ?User $user;

    private ?PasswordCredential $credential;

    public function __construct(User $user, ?PasswordCredential $credential)
    {
        $this->id = $user->id;
        $this->username = self::username($user->username);
        $this->enabled = $user->isEnabled();
        $this->password = $credential === null ? null : CorePasswordHasher::encode($credential->hash);
        $this->user = $user;
        $this->credential = $credential;
    }

    /**
     * The user of the core, when this adapter was built by the provider during this request; an adapter
     * restored from the HTTP session holds none and is refreshed by the provider before it is used.
     */
    public function user(): User
    {
        return $this->user ?? throw new LogicException('This user was restored from the session; refresh it through the provider first.');
    }

    public function passwordCredential(): ?PasswordCredential
    {
        if ($this->user === null) {
            throw new LogicException('This user was restored from the session; refresh it through the provider first.');
        }

        return $this->credential;
    }

    /**
     * @return non-empty-string
     */
    public function getUserIdentifier(): string
    {
        return $this->username;
    }

    /**
     * @return non-empty-list<string>
     */
    public function getRoles(): array
    {
        return [self::ROLE];
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * The same user as long as the identifier and the hash did not change: a password change signs every
     * other browser out, a rename does not.
     */
    public function isEqualTo(UserInterface $user): bool
    {
        return $user instanceof self && $user->id->equals($this->id) && $user->password === $this->password;
    }

    /**
     * @return array{id: string, username: string, enabled: bool, password: string|null}
     */
    public function __serialize(): array
    {
        return [
            'id' => $this->id->toRfc4122(),
            'username' => $this->username,
            'enabled' => $this->enabled,
            'password' => $this->password,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        $id = $data['id'] ?? null;
        $username = $data['username'] ?? null;
        $enabled = $data['enabled'] ?? null;
        $password = $data['password'] ?? null;
        if (! is_string($id) || ! Uuid::isValid($id) || ! is_string($username) || ! is_bool($enabled) || ($password !== null && ! is_string($password))) {
            throw new LogicException('The serialised user is not one this class wrote.');
        }
        $this->id = Uuid::fromString($id);
        $this->username = self::username($username);
        $this->enabled = $enabled;
        $this->password = $password;
        $this->user = null;
        $this->credential = null;
    }

    /**
     * @return non-empty-string
     */
    private static function username(string $username): string
    {
        if ($username === '') {
            throw new LogicException('A user of the core has a username.');
        }

        return $username;
    }
}
