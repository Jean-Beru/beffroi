<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use function is_array;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * The options of a passkey ceremony between the two requests it takes (architecture §5.2): drawn for the
 * browser, kept in its HTTP session, read back once when the response comes, so that a challenge is
 * answered at most once (WebAuthn Level 3 §13.4.3) and by the browser it was drawn for. One ceremony of
 * each kind at a time per browser; the creation options remember the user they were drawn for.
 */
final readonly class PasskeyOptionsStore
{
    public const string CREATION_KEY = 'heidi.passkey.creation';

    public const string REQUEST_KEY = 'heidi.passkey.request';

    public function storeCreation(SessionInterface $session, Uuid $userId, PublicKeyCredentialCreationOptions $options): void
    {
        $session->set(self::CREATION_KEY, [
            'user' => $userId->toRfc4122(),
            'options' => $options,
        ]);
    }

    /**
     * The creation options drawn for this user, or null when none were, or they were for someone else.
     */
    public function takeCreation(SessionInterface $session, Uuid $userId): ?PublicKeyCredentialCreationOptions
    {
        $stored = $session->remove(self::CREATION_KEY);
        if (! is_array($stored) || ($stored['user'] ?? null) !== $userId->toRfc4122()) {
            return null;
        }
        $options = $stored['options'] ?? null;

        return $options instanceof PublicKeyCredentialCreationOptions ? $options : null;
    }

    public function storeRequest(SessionInterface $session, PublicKeyCredentialRequestOptions $options): void
    {
        $session->set(self::REQUEST_KEY, $options);
    }

    public function takeRequest(SessionInterface $session): ?PublicKeyCredentialRequestOptions
    {
        $options = $session->remove(self::REQUEST_KEY);

        return $options instanceof PublicKeyCredentialRequestOptions ? $options : null;
    }
}
