<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class AuthorizationAnswerTest extends TestCase
{
    /**
     * JARM §2.1
     */
    #[Test]
    public function aSignedAnswerCarriesTheDocumentAndNothingElse(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());
        $answer = new AuthorizationAnswer($client, new RedirectUri('https://spa.example/callback'), [
            'code' => 'the-code',
            'state' => 'state-of-the-client',
            'iss' => 'https://id.acme.example',
        ]);

        // When
        $signed = $answer->signedWith('the.signed.document');

        // Then
        static::assertSame(
            [
                'response' => 'the.signed.document',
            ],
            $signed->parameters,
        );
        static::assertSame($client, $signed->client);
        static::assertSame($answer->redirectUri, $signed->redirectUri);
    }

    #[Test]
    public function anAnswerWithoutAParameterIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An answer of the authorization endpoint carries at least one parameter.');

        // When
        new AuthorizationAnswer(Clients::public(Fixtures::tenant()), new RedirectUri('https://spa.example/callback'), []);
    }
}
