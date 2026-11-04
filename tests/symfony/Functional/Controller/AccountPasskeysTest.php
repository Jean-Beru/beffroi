<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Event\CredentialRenamed;
use Beffroi\Core\Domain\Event\CredentialRevoked;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function ksort;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function str_repeat;
use function strlen;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §5.2
 */
final class AccountPasskeysTest extends PasskeyTestCase
{
    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/passkeys');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function thePageListsNothingForAUserWithoutAPasskey(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->passkeysPage();

        // Then
        self::assertInteractionHeaders($this->browser->getResponse());
        static::assertCount(1, $crawler->filter('table[data-passkeys="0"] tr[data-empty]'));
        static::assertCount(0, $crawler->filter('table tbody tr[data-passkey]'));
        static::assertSame('/passkey.js', $crawler->filter('script')->attr('src'));
        $form = $crawler->filter('form[data-passkey="enrol"]');
        static::assertSame('/account/passkeys', $form->attr('action'));
        static::assertSame('/account/passkeys/options', $form->attr('data-options-url'));
        static::assertNotNull($form->attr('hidden'), 'The form waits for the script to find a capable browser.');
        static::assertCount(1, $form->filter('input[name="name"]'));
    }

    /**
     * WebAuthn Level 3 §5.4
     */
    #[Test]
    public function theCreationOptionsAreForThisUserAndThisTenant(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('POST', '/account/passkeys/options');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        self::assertInteractionHeaders($response);
        $options = json_decode(self::string($response->getContent()), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($options);
        static::assertSame(
            [
                'id' => 'op.test',
                'name' => 'op.test',
            ],
            self::sorted($options['rp']),
        );
        $user = self::sorted($options['user']);
        static::assertSame('alice', $user['name']);
        static::assertSame(86, strlen(self::string($user['id'])), 'A 64-byte handle in base64url.');
        static::assertSame(
            [
                'requireResidentKey' => true,
                'residentKey' => 'required',
                'userVerification' => 'preferred',
            ],
            self::sorted($options['authenticatorSelection']),
        );
        static::assertSame('none', $options['attestation']);
        static::assertSame([], $options['excludeCredentials']);
    }

    #[Test]
    public function theCreationOptionsNeedASessionOfTheCore(): void
    {
        // When
        $this->browser->request('POST', '/account/passkeys/options');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame(
            [
                'error' => 'login_required',
            ],
            self::json($response),
        );
    }

    #[Test]
    public function aPasskeyIsEnrolledFromTheSessionAndListed(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        $options = $this->creationOptions();

        // When
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'YubiKey 5',
            '_passkey' => $device->create($options),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/account/passkeys', $response->headers->get('Location'));
        $enrolled = self::events(CredentialEnrolled::class);
        static::assertCount(1, $enrolled);
        static::assertSame('127.0.0.1', $enrolled[0]->context->ipAddress);
        $passkey = self::passkeyOf($alice, $device);
        static::assertSame('YubiKey 5', $passkey->name);
        static::assertTrue($passkey->user->id->equals($alice->id));
        $row = $this->passkeysPage()->filter('table[data-passkeys="1"] tr[data-passkey="' . $passkey->id . '"]');
        static::assertCount(1, $row);
        static::assertSame('no', $row->attr('data-revoked'));
        static::assertSame('YubiKey 5', $row->filter('form[data-passkey="rename"] input[name="name"]')->attr('value'));
    }

    /**
     * WebAuthn Level 3 §5.4
     */
    #[Test]
    public function aSecondPasskeyIsDrawnWithTheFirstExcluded(): void
    {
        // Given
        $alice = self::user('alice');
        $first = $this->enrol($alice, self::device(), 'First');

        // When
        $options = json_decode($this->creationOptions(), true, 8, JSON_THROW_ON_ERROR);

        // Then
        static::assertIsArray($options);
        static::assertSame(
            [
                [
                    'type' => 'public-key',
                    'id' => Base64UrlSafe::encodeUnpadded($first->credentialId),
                    'transports' => ['usb'],
                ],
            ],
            $options['excludeCredentials'],
        );
        static::assertSame(Base64UrlSafe::encodeUnpadded($first->userHandle->value), self::sorted($options['user'])['id']);
    }

    /**
     * @param callable(self, string): Crawler $post
     */
    #[Test]
    #[DataProvider('provideRefusedEnrolments')]
    public function anEnrolmentThatDoesNotHoldIsRefusedWithItsReason(callable $post, string $error): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');
        static::assertIsString($token);

        // When
        $post($this, $token);

        // Then
        static::assertSame($error, $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasskeyCredential::class));
        static::assertSame([], self::events(CredentialEnrolled::class));
    }

    /**
     * @return iterable<string, array{callable(self, string): Crawler, string}>
     */
    public static function provideRefusedEnrolments(): iterable
    {
        yield 'no name' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => '   ',
                '_passkey' => self::device()->create($test->creationOptions()),
            ]),
            'invalid_name',
        ];
        yield 'a name too long' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => str_repeat('k', 256),
                '_passkey' => self::device()->create($test->creationOptions()),
            ]),
            'invalid_name',
        ];
        yield 'no ceremony pending' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => 'Key',
                '_passkey' => self::device()
                    ->create('{"rp":{"id":"op.test"},"user":{"id":"' . str_repeat('A', 86) . '"},"challenge":"' . str_repeat('A', 43) . '"}'),
            ]),
            'no_ceremony',
        ];
        yield 'no attestation' => [
            static function (self $test, string $token): Crawler {
                $test->creationOptions();

                return $test->browser->request('POST', '/account/passkeys', [
                    '_token' => $token,
                    'name' => 'Key',
                    '_passkey' => '',
                ]);
            },
            'no_ceremony',
        ];
        yield 'an attestation from another origin' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => 'Key',
                '_passkey' => self::device()->atOrigin('https://phishing.example')->create($test->creationOptions()),
            ]),
            'refused',
        ];
        yield 'an attestation for another relying party' => [
            static fn (self $test, string $token) => $test->browser->request('POST', '/account/passkeys', [
                '_token' => $token,
                'name' => 'Key',
                '_passkey' => self::device()->forRelyingParty('other.test')->create($test->creationOptions()),
            ]),
            'refused',
        ];
        yield 'an attestation of another challenge' => [
            static function (self $test, string $token): Crawler {
                $stale = $test->creationOptions();
                $test->creationOptions();

                return $test->browser->request('POST', '/account/passkeys', [
                    '_token' => $token,
                    'name' => 'Key',
                    '_passkey' => self::device()->create($stale),
                ]);
            },
            'refused',
        ];
    }

    /**
     * WebAuthn Level 3 §7.1, step 26
     */
    #[Test]
    public function aPasskeyEnrolledTwiceIsRefusedTheSecondTime(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $this->enrol($alice, $device);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');

        // When
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'Again',
            '_passkey' => $device->create($this->creationOptions()),
        ]);

        // Then
        static::assertSame('refused', $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
        static::assertCount(1, self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasskeyCredential::class));
    }

    #[Test]
    public function anEnrolmentWithoutItsTokenIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $options = $this->creationOptions();

        // When
        $crawler = $this->browser->request('POST', '/account/passkeys', [
            '_token' => 'not-the-token',
            'name' => 'Key',
            '_passkey' => self::device()->create($options),
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_csrf_token', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($alice, PasskeyCredential::class));
    }

    #[Test]
    public function theOptionsOfAnotherUserAreNotUsed(): void
    {
        // Given
        $alice = self::user('alice');
        $bob = self::user('bob', 'bob-subject');
        $this->signIn($alice);
        $options = $this->creationOptions();
        $this->signIn($bob);
        $token = $this->passkeysPage()->filter('form[data-passkey="enrol"] input[name="_token"]')->attr('value');

        // When
        $this->browser->request('POST', '/account/passkeys', [
            '_token' => $token,
            'name' => 'Key',
            '_passkey' => self::device()->create($options),
        ]);

        // Then
        static::assertSame('no_ceremony', $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
        static::assertSame([], self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($bob, PasskeyCredential::class));
    }

    #[Test]
    public function aPasskeyIsRevokedFromThePage(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $form = $this->passkeysPage()
            ->filter('tr[data-passkey="' . $passkey->id . '"]')
            ->selectButton('Revoke')
            ->form();

        // When
        $this->browser->submit($form);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/account/passkeys', $response->headers->get('Location'));
        $revoked = self::events(CredentialRevoked::class);
        static::assertCount(1, $revoked);
        static::assertTrue(self::passkeyOf($alice, $device)->isRevoked());
        $row = $this->passkeysPage()->filter('tr[data-passkey="' . $passkey->id . '"]');
        static::assertSame('yes', $row->attr('data-revoked'));
        static::assertCount(0, $row->filter('button'), 'No revoking twice.');
    }

    #[Test]
    public function aRevokedPasskeyNoLongerSignsIn(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->browser->submit(
            $this->passkeysPage()
                ->filter('tr[data-passkey="' . $passkey->id . '"]')
                ->selectButton('Revoke')
                ->form(),
        );
        $this->forgetTheBrowser();
        $interaction = $this->authorize();

        // When
        $this->loginWithPasskey($interaction, $device);

        // Then
        static::assertFalse($this->isBoundToASession());
    }

    #[Test]
    public function somebodyElsesPasskeyIsNotFoundToRevoke(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $bob = self::user('bob', 'bob-subject');
        $own = $this->enrol($bob, self::device());
        $token = $this->passkeysPage()
            ->filter('tr[data-passkey="' . $own->id . '"] form[data-passkey="revoke"] input[name="_token"]')
            ->attr('value');

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
    }

    #[Test]
    public function aPasskeyIsNamedAgainFromItsOwnLine(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $form = $this->passkeysPage()
            ->filter('tr[data-passkey="' . $passkey->id . '"] form[data-passkey="rename"]')
            ->form();
        $form->setValues([
            'name' => 'The key of my telephone',
        ]);

        // When
        $this->browser->submit($form);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('The key of my telephone', self::passkeyOf($alice, $device)->name);
        $renamed = self::events(CredentialRenamed::class);
        static::assertCount(1, $renamed);
        static::assertSame('YubiKey 5', $renamed[0]->was);
    }

    #[Test]
    public function aNameAPasskeyCannotHoldIsRefused(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $token = self::string(
            $this->passkeysPage()
                ->filter('tr[data-passkey="' . $passkey->id . '"] form[data-passkey="rename"] input[name="_token"]')
                ->attr('value'),
        );

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/name', [
            '_token' => $token,
            'name' => str_repeat('k', 256),
        ]);

        // Then
        static::assertSame('invalid_name', $this->afterTheForm()->filter('p[data-error]')->attr('data-error'));
        static::assertSame('YubiKey 5', self::passkeyOf($alice, $device)->name);
        static::assertSame([], self::events(CredentialRenamed::class));
    }

    #[Test]
    public function somebodyElsesPasskeyIsNotFoundToName(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->forgetTheBrowser();
        $bob = self::user('bob', 'bob-subject');
        $own = $this->enrol($bob, self::device());
        $token = self::string(
            $this->passkeysPage()
                ->filter('tr[data-passkey="' . $own->id . '"] form[data-passkey="rename"] input[name="_token"]')
                ->attr('value'),
        );

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/name', [
            '_token' => $token,
            'name' => 'Not mine',
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame('YubiKey 5', self::passkeyOf($alice, $device)->name);
    }

    #[Test]
    public function aRevokedPasskeyIsNotNamedAgain(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->browser->submit(
            $this->passkeysPage()
                ->filter('tr[data-passkey="' . $passkey->id . '"]')
                ->selectButton('Revoke')
                ->form(),
        );

        // When
        $row = $this->passkeysPage()->filter('tr[data-passkey="' . $passkey->id . '"]');

        // Then
        static::assertCount(0, $row->filter('form[data-passkey="rename"]'));
        static::assertStringContainsString('YubiKey 5', $row->text());
    }

    #[Test]
    public function aRevocationWithoutItsTokenIsRefused(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);

        // When
        $crawler = $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => 'not-the-token',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_csrf_token', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
    }

    #[Test]
    public function aRevocationNeedsASessionOfTheCore(): void
    {
        // Given
        $device = self::device();
        $alice = self::user('alice');
        $passkey = $this->enrol($alice, $device);
        $this->forgetTheBrowser();

        // When
        $this->browser->request('POST', '/account/passkeys/' . $passkey->id . '/revoke', [
            '_token' => 'whatever',
        ]);

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::passkeyOf($alice, $device)->isRevoked());
    }

    #[Test]
    public function thePageSpeaksTheLanguageOfTheBrowser(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/account/passkeys', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Vos passkeys', $crawler->filter('h1')->text());
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function theScriptIsServedByTheProvider(): void
    {
        // When
        $this->browser->request('GET', '/passkey.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('public'));
        static::assertSame('3600', $response->headers->getCacheControlDirective('max-age'));
        static::assertNotNull($response->headers->get('ETag'));
        $script = $this->browser->getInternalResponse()->getContent();
        static::assertStringContainsString('navigator.credentials.get(', $script);
        static::assertStringContainsString('navigator.credentials.create(', $script);
    }

    /**
     * @return array<string, mixed>
     */
    private static function sorted(mixed $object): array
    {
        static::assertIsArray($object);
        $sorted = [];
        foreach ($object as $key => $value) {
            $sorted[(string) $key] = $value;
        }
        ksort($sorted);

        return $sorted;
    }

    #[Test]
    public function theScriptIsNotSentAgainToABrowserThatHasIt(): void
    {
        // Given
        $this->browser->request('GET', '/passkey.js');
        $etag = $this->browser->getResponse()->headers->get('ETag');

        // When
        $this->browser->request('GET', '/passkey.js', server: [
            'HTTP_IF_NONE_MATCH' => $etag,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_MODIFIED, $this->browser->getResponse()->getStatusCode());
    }
}
