<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Domain\Credential\Attestation\ModelProof;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * WebAuthn Level 3 §5.4.7, §8.2.2, Decision 0046
 */
final class EnterprisePasskeyAttestationTest extends PasskeyAttestationTestCase
{
    private static ?AttestationAuthority $organisation = null;

    protected static function policy(): array
    {
        return [
            'BEFFROI_TEST_PASSKEY_ATTESTATION' => 'enterprise',
            'BEFFROI_TEST_PASSKEY_ATTESTATION_ROOTS' => [self::organisation()->rootCertificate()],
        ];
    }

    #[Test]
    public function theCreationOptionsAskForAnEnterpriseAttestation(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $options = json_decode($this->creationOptions(), true, 8, JSON_THROW_ON_ERROR);

        // Then
        static::assertIsArray($options);
        static::assertSame('enterprise', $options['attestation'] ?? null);
    }

    #[Test]
    public function aKeyTheOrganisationAttestedIsEnrolledAndThePageShowsItsSerialNumber(): void
    {
        // Given
        $alice = self::user('alice');

        // When
        $page = $this->tryToEnrol($alice, $this->attested(self::organisation()->attest("\x0A\xDA")));

        // Then
        $passkey = self::passkeysOf($alice)[0];
        static::assertSame(ModelProof::Enterprise, $passkey->modelProof);
        static::assertSame('0ada', $passkey->serialNumber);
        static::assertSame('0ada', $page->filter('[data-serial-number]')->attr('data-serial-number'));
        static::assertSame('enterprise', $page->filter('[data-model-proof]')->attr('data-model-proof'));
    }

    #[Test]
    public function aKeyAnotherAuthorityAttestedIsRefusedAndThePageSaysTheOrganisationAcceptsItsOwnKeysOnly(): void
    {
        // Given
        $alice = self::user('alice');

        // When
        $page = $this->tryToEnrol($alice, $this->attested(AttestationAuthority::create('A maker the organisation does not pin')->attest("\x01")));

        // Then
        static::assertSame([], self::passkeysOf($alice));
        static::assertSame('organisation_keys_only', $page->filter('p[data-error]')->attr('data-error'));
        static::assertSame('Only the keys your organisation gave you are accepted.', $page->filter('p[data-error]')->text());
    }

    #[Test]
    public function aKeyRefusedThroughATicketLeavesTheLinkAndThePageSaysWhy(): void
    {
        // Given
        $alice = self::user('alice');
        $issued = self::service('test.beffroi.enrolment_tickets', EnrolmentTicketIssue::class)
            ->issue(
                self::service('test.beffroi.users', UserRepositoryInterface::class)->find($alice->id) ?? static::fail('The person is gone.'),
                self::context(),
            );
        $path = '/enrol/' . $issued->ticket->id->toRfc4122() . '/' . $issued->value;
        $token = $this->browser->request('GET', $path)->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);
        $this->browser->request('POST', $path . '/options');
        $options = self::string($this->browser->getResponse()->getContent());

        // When
        $this->browser->request('POST', $path, [
            '_token' => $token,
            '_passkey' => self::device()->create($options),
            'name' => 'A key of nobody',
        ]);

        // Then
        static::assertSame(Response::HTTP_SEE_OTHER, $this->browser->getResponse()->getStatusCode());
        $page = $this->afterTheForm();
        static::assertSame('organisation_keys_only', $page->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::passkeysOf($alice));
    }

    private static function organisation(): AttestationAuthority
    {
        return self::$organisation ??= AttestationAuthority::create('Organisation of the tests');
    }
}
