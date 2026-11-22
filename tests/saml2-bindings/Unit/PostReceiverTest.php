<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_encode;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\Exception\InvalidRelayState;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Exception\MalformedParameters;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\ReceivedResponse;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use function chunk_split;
use function gzdeflate;
use function is_string;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rawurldecode;
use function str_repeat;
use function strlen;
use function substr_replace;
use const ZLIB_ENCODING_RAW;

/**
 * Section 6.2 steps 1 to 6, sections 9.2 and 9.3, B-1, B-7, B-8, B-9, B-10, M-1, section 8, SAML Bindings §3.5.4
 *
 * @phpstan-type Method 'response'|'authnRequest'|'logoutMessage'
 */
final class PostReceiverTest extends TestCase
{
    use ReceptionFixtures;

    private const string RELAY_STATE = '€€€€€€€€€€€€€€€€€€€€€€€€ &=+%;ab';

    /**
     * Section 6.2 step 6, M-1, SAML Bindings §3.5.4
     */
    #[Test]
    public function itReceivesAResponse(): void
    {
        // When
        $received = self::postReceiver()->response(self::form('SAMLResponse', self::fixture(self::RESPONSE)));

        // Then
        static::assertSame(
            ['https://idp.example.com/saml', self::RESPONSE_REQUEST_ID, null, Binding::HttpPost],
            [
                $received->response->issuer,
                $received->response->inResponseTo,
                $received->relayState,
                $received->binding,
            ],
        );
    }

    /**
     * Section 6.2 step 6, M-1, SAML Bindings §3.5.4
     */
    #[Test]
    public function itReceivesAnAuthnRequest(): void
    {
        // When
        $received = self::postReceiver()->authnRequest(self::form('SAMLRequest', self::fixture(self::AUTHN_REQUEST)));

        // Then
        static::assertSame(
            ['https://sp.example.com/saml', null, Binding::HttpPost],
            [$received->request->issuer, $received->relayState, $received->binding],
        );
    }

    /**
     * Section 6.2 step 6, M-1, SAML Bindings §3.5.4
     */
    #[Test]
    public function itReceivesALogoutRequest(): void
    {
        // When
        $received = self::postReceiver()->logoutMessage(self::form('SAMLRequest', self::fixture(self::LOGOUT_REQUEST)));

        // Then
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);
        static::assertSame(
            ['https://idp.example.com/saml', Binding::HttpPost],
            [$received->request->issuer, $received->binding],
        );
    }

    /**
     * Section 6.2 step 6, M-1, SAML Bindings §3.5.4
     */
    #[Test]
    public function itReceivesALogoutResponse(): void
    {
        // When
        $received = self::postReceiver()->logoutMessage(self::form('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE)));

        // Then
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);
        static::assertSame(
            ['https://sp.example.com/saml', self::LOGOUT_REQUEST_ID, Binding::HttpPost],
            [$received->response->issuer, $received->response->inResponseTo, $received->binding],
        );
    }

    /**
     * §9.3 row 5, B-9, section 8, SAML Bindings §3.5.3
     *
     * @param Method $method
     */
    #[Test]
    #[DataProvider('provideRelayStates')]
    public function itReturnsRelayStateAsPosted(
        string $method,
        string $field,
        string $fixture,
        ?string $relayState,
    ): void {
        // When
        $received = $this->receive($method, self::form($field, self::fixture($fixture), $relayState));

        // Then
        static::assertSame($relayState, $received->relayState);
    }

    /**
     * @return iterable<string, array{Method, string, string, ?string}>
     */
    public static function provideRelayStates(): iterable
    {
        yield 'a response, none' => ['response', 'SAMLResponse', self::RESPONSE, null];
        yield 'a response, exactly 80 bytes' => ['response', 'SAMLResponse', self::RESPONSE, self::RELAY_STATE];
        yield 'an AuthnRequest, exactly 80 bytes' => [
            'authnRequest',
            'SAMLRequest',
            self::AUTHN_REQUEST,
            self::RELAY_STATE,
        ];
        yield 'a LogoutResponse, exactly 80 bytes' => [
            'logoutMessage',
            'SAMLResponse',
            self::LOGOUT_RESPONSE,
            self::RELAY_STATE,
        ];
        yield 'a response, exactly 1 024 bytes' => [
            'response',
            'SAMLResponse',
            self::RESPONSE,
            self::relayStateOf1024Bytes(),
        ];
        yield 'an AuthnRequest, exactly 1 024 bytes' => [
            'authnRequest',
            'SAMLRequest',
            self::AUTHN_REQUEST,
            self::relayStateOf1024Bytes(),
        ];
    }

    /**
     * §9.2 row 2, B-1, CVE-2025-27773
     *
     * @param Method $method
     * @param list<array{string, string}> $fields
     */
    #[Test]
    #[DataProvider('provideBothMessageFields')]
    public function itRefusesBothMessageFields(string $method, array $fields): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries both SAMLRequest and SAMLResponse (B-1).');

        // When
        $this->receive($method, BrowserForm::posted($fields));
    }

    /**
     * @return iterable<string, array{Method, list<array{string, string}>}>
     */
    public static function provideBothMessageFields(): iterable
    {
        $request = base64_encode(self::fixture(self::AUTHN_REQUEST));
        $response = base64_encode(self::fixture(self::RESPONSE));

        yield 'SAMLRequest first, to response()' => [
            'response',
            [
                ['SAMLRequest',  $request],
                ['SAMLResponse', $response],
            ],
        ];
        yield 'SAMLResponse first, to authnRequest()' => [
            'authnRequest',
            [
                ['SAMLResponse', $response],
                ['SAMLRequest',  $request],
            ],
        ];
        yield 'SAMLRequest first, to logoutMessage()' => [
            'logoutMessage',
            [
                ['SAMLRequest',  $request],
                ['RelayState',   'state'],
                ['SAMLResponse', $response],
            ],
        ];
    }

    /**
     * §9.2 row 3, B-1
     *
     * @param Method $method
     */
    #[Test]
    #[DataProvider('provideEveryMethod')]
    public function itRefusesAFormWithoutMessageField(string $method): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries neither SAMLRequest nor SAMLResponse (B-1).');

        // When
        $this->receive($method, BrowserForm::posted([
            ['RelayState', 'state'],
            ['submit',     'Submit'],
        ]));
    }

    /**
     * @return iterable<string, array{Method}>
     */
    public static function provideEveryMethod(): iterable
    {
        yield 'response()' => ['response'];
        yield 'authnRequest()' => ['authnRequest'];
        yield 'logoutMessage()' => ['logoutMessage'];
    }

    /**
     * §9.2 row 4, B-1
     *
     * @param Method $method
     */
    #[Test]
    #[DataProvider('provideMessageFieldsTheMethodDoesNotTake')]
    public function itRefusesAMessageFieldTheMethodDoesNotTake(string $method, string $field, string $fixture): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries a message field the method does not take (B-1).');

        // When
        $this->receive($method, self::form($field, self::fixture($fixture)));
    }

    /**
     * @return iterable<string, array{Method, string, string}>
     */
    public static function provideMessageFieldsTheMethodDoesNotTake(): iterable
    {
        yield 'a SAMLResponse given to authnRequest()' => ['authnRequest', 'SAMLResponse', self::RESPONSE];
        yield 'a SAMLRequest given to response()' => ['response', 'SAMLRequest', self::AUTHN_REQUEST];
    }

    /**
     * §9.2 row 8, B-1
     *
     * @param Method $method
     * @param list<array{string, string}> $fields
     */
    #[Test]
    #[DataProvider('provideArrayFields')]
    public function itRefusesAnArrayField(string $method, array $fields): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('A field of the binding is not a string, an array for instance (B-1).');

        // When
        $this->receive($method, BrowserForm::posted($fields));
    }

    /**
     * @return iterable<string, array{Method, list<array{string, string}>}>
     */
    public static function provideArrayFields(): iterable
    {
        $response = base64_encode(self::fixture(self::RESPONSE));

        yield 'SAMLResponse[]' => ['response', [['SAMLResponse[]', $response]]];
        yield 'SAMLResponse[0]' => ['response', [['SAMLResponse[0]', $response]]];
        yield 'RelayState[], after a SAMLResponse' => [
            'response',
            [
                ['SAMLResponse', $response],
                ['RelayState[]', 'state'],
            ],
        ];
        yield 'SAMLRequest[]' => [
            'authnRequest',
            [['SAMLRequest[]', base64_encode(self::fixture(self::AUTHN_REQUEST))]],
        ];
    }

    /**
     * §9.2 row 29, section 8, SAML Bindings §3.5.4
     *
     * @param Method $method
     * @param list<array{string, string}> $fields
     */
    #[Test]
    #[DataProvider('provideFormsWithADetachedSignature')]
    public function itRefusesADetachedSignatureInAForm(string $method, array $fields): void
    {
        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('SigAlg or Signature in a form is refused: HTTP-POST carries no detached signature (section 8).');

        // When
        $this->receive($method, BrowserForm::posted($fields));
    }

    /**
     * @return iterable<string, array{Method, list<array{string, string}>}>
     */
    public static function provideFormsWithADetachedSignature(): iterable
    {
        $signed = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))->signed();
        $sigAlg = rawurldecode($signed->value('SigAlg'));
        $signature = rawurldecode($signed->value('Signature'));
        $request = base64_encode(self::fixture(self::AUTHN_REQUEST));

        yield 'SigAlg and Signature, to authnRequest()' => [
            'authnRequest',
            [
                ['SAMLRequest', $request],
                ['SigAlg',      $sigAlg],
                ['Signature',   $signature],
            ],
        ];
        yield 'SigAlg alone, to logoutMessage()' => [
            'logoutMessage',
            [['SAMLResponse', base64_encode(self::fixture(self::LOGOUT_RESPONSE))], ['SigAlg', $sigAlg]],
        ];
        yield 'Signature alone, to response()' => [
            'response',
            [['SAMLResponse', base64_encode(self::fixture(self::RESPONSE))], ['Signature', $signature]],
        ];
    }

    /**
     * §9.2 row 23, B-7, section 6.2 step 2
     */
    #[Test]
    public function itRefusesAMessageFieldOverTheBound(): void
    {
        // Given
        $form = self::form('SAMLResponse', self::fixture(self::RESPONSE));
        $bound = strlen(base64_encode(self::fixture(self::RESPONSE))) - 1;

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The message field is longer than maxFormValueBytes, ' . $bound . ' bytes (B-7).');

        // When
        new PostReceiver(SamlLoader::create(), new BindingLimits(maxFormValueBytes: $bound))->response($form);
    }

    /**
     * B-7, section 6.2 step 2, section 7
     */
    #[Test]
    public function itReceivesAMessageFieldOfExactlyTheBound(): void
    {
        // Given
        $form = self::form('SAMLResponse', self::fixture(self::RESPONSE));
        $bound = strlen(base64_encode(self::fixture(self::RESPONSE)));

        // When
        $received = new PostReceiver(
            SamlLoader::create(),
            new BindingLimits(maxFormValueBytes: $bound),
        )->response($form);

        // Then
        static::assertSame(self::RESPONSE_REQUEST_ID, $received->response->inResponseTo);
    }

    /**
     * §9.2 row 7, B-8, section 6.2 step 2
     *
     * @param Method $method
     */
    #[Test]
    #[DataProvider('provideEmptyMessageFields')]
    public function itRefusesAnEmptyMessageField(string $method, string $field): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The message field is empty (B-8).');

        // When
        $this->receive($method, BrowserForm::posted([[$field, '']]));
    }

    /**
     * @return iterable<string, array{Method, string}>
     */
    public static function provideEmptyMessageFields(): iterable
    {
        yield 'an empty SAMLResponse, to response()' => ['response', 'SAMLResponse'];
        yield 'an empty SAMLRequest, to authnRequest()' => ['authnRequest', 'SAMLRequest'];
    }

    /**
     * §9.2 row 16, B-9, section 8, SAML Bindings §3.5.3
     */
    #[Test]
    #[DataProvider('provideRelayStatesOutsideTheBounds')]
    public function itRefusesARelayStateOutsideItsBounds(string $relayState, string $message): void
    {
        // Then
        $this->expectException(InvalidRelayState::class);
        $this->expectExceptionMessageIs($message);

        // When
        self::postReceiver()->response(self::form('SAMLResponse', self::fixture(self::RESPONSE), $relayState));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRelayStatesOutsideTheBounds(): iterable
    {
        yield '1 025 bytes' => [self::relayStateOf1024Bytes() . 'x', 'The RelayState is longer than 1024 bytes (B-9).'];
        yield 'empty' => ['', 'The RelayState is empty (B-9).'];
    }

    /**
     * §9.2 row 25, B-8, section 6.2 step 4, RFC 2045 §6.8
     */
    #[Test]
    #[DataProvider('provideWhitespaceOtherThanLineBreaks')]
    public function itRefusesWhitespaceOtherThanLineBreaks(string $whitespace): void
    {
        // Given
        $form = BrowserForm::posted([[
            'SAMLResponse',
            substr_replace(
                base64_encode(self::fixture(self::RESPONSE)),
                $whitespace,
                76,
                0,
            ),
        ]]);

        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A base64 value is not in its one form: the alphabet and the padding of RFC 4648 section 4, the unused bits zero, no whitespace (B-8).');

        // When
        self::postReceiver()->response($form);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhitespaceOtherThanLineBreaks(): iterable
    {
        yield 'a space' => [' '];
        yield 'a tab' => ["\t"];
        yield 'a space before a line feed' => [" \n"];
    }

    /**
     * §9.3 row 9, B-8, section 6.2 step 4, RFC 2045 §6.8
     */
    #[Test]
    #[DataProvider('provideLineBreaks')]
    public function itReceivesAValueWrappedAt76Characters(string $lineBreak): void
    {
        // Given
        $form = BrowserForm::posted([[
            'SAMLResponse',
            chunk_split(
                base64_encode(self::fixture(self::RESPONSE)),
                76,
                $lineBreak,
            ),
        ]]);
        $received = self::postReceiver()->response($form);

        // When
        $accepted = $received->validate(self::responseValidator(), self::identityProvider(), self::expectedResponse());

        // Then
        static::assertSame(['_response', SignatureCoverage::Assertion], [$accepted->responseId, $accepted->coverage]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLineBreaks(): iterable
    {
        yield 'CR LF' => ["\r\n"];
        yield 'LF' => ["\n"];
    }

    /**
     * §9.3 row 10, section 6.2 step 1, SAML Bindings §3.5.4
     */
    #[Test]
    public function itSkipsTheOtherFields(): void
    {
        // Given
        $form = BrowserForm::posted([
            ['submit', 'Submit'],
            ['SAMLResponse', base64_encode(self::fixture(self::RESPONSE))],
            ['RelayState', 'state'],
            ['lang', 'fr'],
        ]);

        // When
        $received = self::postReceiver()->response($form);

        // Then
        static::assertSame(
            [self::RESPONSE_REQUEST_ID, 'state'],
            [$received->response->inResponseTo, $received->relayState],
        );
    }

    /**
     * §9.2 row 30, B-8, section 6.2 step 4, SAML Bindings §3.5.4
     */
    #[Test]
    public function itNeverInflatesAPostedMessage(): void
    {
        // Given
        $deflated = gzdeflate(self::fixture(self::AUTHN_REQUEST), -1, ZLIB_ENCODING_RAW);
        if (! is_string($deflated)) {
            throw new LogicException('zlib failed on a fixture.');
        }

        // Then
        $this->expectException(EncodingRefused::class);
        $this->expectExceptionMessageIs('The input is not valid UTF-8 (I-5).');

        // When
        self::postReceiver()->authnRequest(self::form('SAMLRequest', $deflated));
    }

    /**
     * §9.2 row 31, section 6.2 step 6, M-1, SAML Bindings §3.5.4
     *
     * @param Method $method
     */
    #[Test]
    #[DataProvider('provideMessagesOfAnotherRoot')]
    public function itRefusesAMessageOfAnotherRoot(
        string $method,
        string $field,
        string $fixture,
        string $message,
    ): void {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->receive($method, self::form($field, self::fixture($fixture)));
    }

    /**
     * @return iterable<string, array{Method, string, string, string}>
     */
    public static function provideMessagesOfAnotherRoot(): iterable
    {
        yield 'a samlp:Response given to logoutMessage()' => [
            'logoutMessage',
            'SAMLResponse',
            self::RESPONSE,
            'The root of the message is not a samlp:LogoutResponse (section 5.4).',
        ];
        yield 'a LogoutResponse given to response()' => [
            'response',
            'SAMLResponse',
            self::LOGOUT_RESPONSE,
            'The root of the document is not a samlp:Response (M-1).',
        ];
        yield 'an AuthnRequest in a SAMLResponse given to logoutMessage()' => [
            'logoutMessage',
            'SAMLResponse',
            self::AUTHN_REQUEST,
            'The root of the message is not a samlp:LogoutResponse (section 5.4).',
        ];
        yield 'a LogoutResponse in a SAMLRequest' => [
            'logoutMessage',
            'SAMLRequest',
            self::LOGOUT_RESPONSE,
            'The root of the message is not a samlp:LogoutRequest (section 5.4).',
        ];
        yield 'a LogoutRequest given to authnRequest()' => [
            'authnRequest',
            'SAMLRequest',
            self::LOGOUT_REQUEST,
            'The root of the document is not a samlp:AuthnRequest (section 6.2).',
        ];
    }

    /**
     * §9.2 row 32, B-10, I-1, SAML Bindings §3.5.4
     */
    #[Test]
    public function itLetsCoreRefuseADoctype(): void
    {
        // Given
        $form = self::form('SAMLRequest', self::fixture('hostile/authn-request-doctype-refused.xml'));

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The input contains a document type declaration (I-1).');

        // When
        self::postReceiver()->authnRequest($form);
    }

    /**
     * §9.2 row 3, B-1
     */
    #[Test]
    public function itRefusesAnEmptyBody(): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries neither SAMLRequest nor SAMLResponse (B-1).');

        // When
        self::postReceiver()->response(BrowserForm::parsed(''));
    }

    /**
     * @param Method                  $method
     * @param array<array-key, mixed> $fields
     */
    private function receive(
        string $method,
        array $fields,
    ): ReceivedAuthnRequest|ReceivedLogoutRequest|ReceivedLogoutResponse|ReceivedResponse {
        return match ($method) {
            'response' => self::postReceiver()->response($fields),
            'authnRequest' => self::postReceiver()->authnRequest($fields),
            'logoutMessage' => self::postReceiver()->logoutMessage($fields),
        };
    }

    /**
     * B-9
     */
    private static function relayStateOf1024Bytes(): string
    {
        return str_repeat(self::RELAY_STATE, 12) . str_repeat('€', 21) . 'a';
    }
}
