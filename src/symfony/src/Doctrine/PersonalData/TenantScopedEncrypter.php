<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\PersonalData;

use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Port\AmbientTenantInterface;
use SensitiveParameter;
use function sprintf;
use function strpos;
use function substr;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\EnvelopeDecrypterInterface;
use Symfony\Component\KeyManagement\EnvelopeEncrypterInterface;
use Throwable;

/**
 * The scope of a sealed column, composed one layer above the type that carries it, and the envelope bound
 * to the tenant it was sealed for (decision 0018).
 *
 * An `EncryptedType` holds its scope as a constant fixed at registration and sees neither the table, nor
 * the column, nor the row: what it is handed is an encrypter, and this is the encrypter that composes. The
 * scope it receives is the family of columns (`EncryptedColumnTypes`), and what it passes on is that family
 * prefixed by the slug of the ambient tenant, which is the only channel between a type and the store: the
 * store returns the newest key of a scope and reads no other column, so two tenants sharing a scope string
 * would share the data key the first write created, which decision 0011 refuses in as many words.
 *
 * The authenticated data of the envelope name the tenant, as `TenantEnvelope` names it for a signing key
 * and for a sealed secret: a ciphertext of one tenant does not open for another, whatever row it is found
 * in. What they do not name is the column, there being nowhere to take it from; that is written on the page
 * for a CISO and not hidden here.
 *
 * **A write with no ambient tenant is refused and never falls back on a scope of its own.** A value sealed
 * outside the scope of its tenant is a value that no destruction of that tenant's keys reaches, which is a
 * hole in the one erasure this provider promises.
 */
/*
 * Not readonly, so that the container can hand it over as a lazy object: what registers the types runs
 * while the bundles boot, and nothing of this chain is built until a column is actually sealed or read.
 */
final readonly class TenantScopedEncrypter implements EnvelopeDecrypterInterface, EnvelopeEncrypterInterface
{
    /**
     * What tells an envelope of a personal datum from an envelope of a signing key or of a sealed secret,
     * and one tenant from another. The wording is the one of the day it was written and it does not
     * change: nothing rewraps an envelope, so every value sealed under it must keep opening under it.
     */
    public const string AAD = 'heidi:personal-data:v1:';

    /**
     * What joins the slug of a tenant to the family of columns in a scope. A slug is one to sixty-three
     * lowercase letters, digits or hyphens (`Tenant`), so it carries no separator of its own and the slug
     * of a scope is what precedes the first one; the longest family of the spike brings the whole to
     * ninety-eight characters, where the column of the store holds a hundred and ninety-one.
     */
    public const string SEPARATOR = '.';

    public function __construct(
        private EnvelopeEncrypterInterface&EnvelopeDecrypterInterface $envelopes,
        private AmbientTenantInterface $tenants,
    ) {
    }

    /**
     * @param string $key the family of columns the type was registered for
     *
     * @throws RuntimeException when no tenant is ambient
     */
    public function encrypt(string $key, #[SensitiveParameter] string $plaintext, string $aad = ''): Envelope
    {
        $slug = $this->slug($key);

        return $this->envelopes->encrypt(self::scope($slug, $key), $plaintext, $aad . self::AAD . $slug);
    }

    /**
     * The scope is not handed to a decryption: the store reads back the client and the master key of the
     * row the reference names, so a read resolves whatever wrote it and routes nothing. What is handed is
     * the tenant, in the authenticated data, which is what refuses the ciphertext of another one.
     *
     * @throws RuntimeException when no tenant is ambient
     */
    public function decrypt(Envelope $envelope, string $aad = ''): string
    {
        return $this->envelopes->decrypt($envelope, $aad . self::AAD . $this->slug(null));
    }

    /**
     * The scope of a family for a tenant, and the one place it is composed.
     */
    public static function scope(string $slug, string $family): string
    {
        return $slug . self::SEPARATOR . $family;
    }

    /**
     * The slug of a scope, which is what precedes the first separator; the whole string when it carries
     * none, so that a scope composed by something else is routed to a tenant of that name rather than to
     * a tenant nobody named.
     */
    public static function slugOf(string $scope): string
    {
        $separator = strpos($scope, self::SEPARATOR);

        return $separator === false ? $scope : substr($scope, 0, $separator);
    }

    /**
     * @param string|null $family what the refusal names, when it is a write; a read names none, having
     *                            only an envelope
     *
     * @throws RuntimeException
     */
    private function slug(?string $family): string
    {
        try {
            return $this->tenants->provide()->slug;
        } catch (Throwable $exception) {
            throw new RuntimeException(
                sprintf(
                    'No tenant is ambient, so %s cannot be %s: a value sealed outside the scope of its tenant is a value no destruction of that tenant\'s keys reaches.',
                    $family === null ? 'a sealed value' : sprintf('a column of the "%s" family', $family),
                    $family === null ? 'read' : 'sealed',
                ),
                0,
                $exception,
            );
        }
    }
}
