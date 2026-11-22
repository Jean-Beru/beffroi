<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function array_filter;
use function array_intersect;
use function array_map;
use function array_values;
use function base64_encode;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\ReceivedResponse;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use function count;
use function dirname;
use function file_get_contents;
use LogicException;
use PhpToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function rawurldecode;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SensitiveParameter;
use SplFileInfo;
use function sprintf;
use function strlen;
use function strrchr;
use function substr;
use const T_ABSTRACT;
use const T_FINAL;
use const T_FUNCTION;
use const T_NAME_FULLY_QUALIFIED;
use const T_NAME_QUALIFIED;
use const T_NAME_RELATIVE;
use const T_PRIVATE;
use const T_PROTECTED;
use const T_PUBLIC;
use const T_READONLY;
use const T_STATIC;
use const T_STRING;
use const T_USE;

/**
 * B-5, section 5.2, SAML Bindings §3.4.4.1, §3.5.4
 *
 * @phpstan-type Path 'receiver, authnRequest()'|'by hand, ReceivedAuthnRequest'|'receiver, logoutMessage()'|'by hand, ReceivedLogoutResponse'
 */
final class PairingTest extends TestCase
{
    use ReceptionFixtures;

    private const array MESSAGES = [
        'Document',
        'UnverifiedAuthnRequest',
        'UnverifiedLogoutRequest',
        'UnverifiedLogoutResponse',
        'UnverifiedResponse',
    ];

    private const array SIGNATURES = ['DetachedSignature', 'SignedOctets', 'QueryParameters'];

    private const array MODIFIERS = [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_FINAL, T_ABSTRACT, T_READONLY];

    /**
     * B-5, section 5.2
     */
    #[Test]
    public function itPairsAMessageWithASignatureInTheReceptionAlone(): void
    {
        // When
        $pairing = array_filter(
            $this->functions(),
            fn (array $function): bool => $this->takesAny($function['types'], self::MESSAGES) && $this->takesAny($function['types'], self::SIGNATURES),
        );

        // Then
        static::assertSame(
            ['Internal/Reception.php __construct private'],
            array_values(array_map(
                static fn (array $function): string => sprintf(
                    '%s %s%s',
                    $function['file'],
                    $function['name'],
                    $function['private'] ? ' private' : '',
                ),
                $pairing,
            )),
        );
    }

    /**
     * B-5, section 5.2
     */
    #[Test]
    public function itBuildsAReceptionFromTheRawInputAlone(): void
    {
        // Given
        $factories = array_filter(
            $this->functions(),
            static fn (array $function): bool => $function['file'] === 'Internal/Reception.php' && $function['name'] !== '__construct',
        );

        // When
        $taking = array_filter(
            $factories,
            fn (array $function): bool => $this->takesAny($function['types'], [...self::MESSAGES, ...self::SIGNATURES]),
        );

        // Then
        static::assertSame(
            ['ofQueryString', 'ofForm'],
            array_values(array_map(static fn (array $function): string => $function['name'], $factories)),
        );
        static::assertSame([], $taking);
    }

    /**
     * B-5, section 5.2
     */
    #[Test]
    #[TestWith(['ReceivedAuthnRequest.php'], 'ReceivedAuthnRequest')]
    #[TestWith(['ReceivedLogoutRequest.php'], 'ReceivedLogoutRequest')]
    #[TestWith(['ReceivedLogoutResponse.php'], 'ReceivedLogoutResponse')]
    #[TestWith(['ReceivedResponse.php'], 'ReceivedResponse')]
    public function itBuildsAReceivedMessageFromAReceptionAlone(string $file): void
    {
        // When
        $constructors = array_filter(
            $this->functions(),
            static fn (array $function): bool => $function['file'] === $file && $function['name'] === '__construct',
        );

        // Then
        static::assertSame(
            [['Reception']],
            array_values(array_map(static fn (array $function): array => $function['types'], $constructors)),
        );
    }

    /**
     * B-1, B-2, B-5, §9.2 row 14, SAML Bindings §3.4.4.1
     *
     * @param Path $path
     */
    #[Test]
    #[DataProvider('providePathsWithTheSignatureOfAnotherMessage')]
    public function itNeverValidatesAMessageUnderTheSignatureOfAnother(string $path, RedirectQuery $query): void
    {
        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the detached signature (D-7, D-8).');

        // When
        $this->validate($path, $query);
    }

    /**
     * @return iterable<string, array{Path, RedirectQuery}>
     */
    public static function providePathsWithTheSignatureOfAnotherMessage(): iterable
    {
        $signed = RedirectQuery::carrying(
            'SAMLRequest',
            self::fixture('behaviour/authn-request-assertion-consumer-service-index.xml'),
        )
            ->withRelayState('state')
            ->signed();
        $inPlace = $signed->replaced('SAMLRequest', RedirectQuery::message(self::fixture(self::AUTHN_REQUEST)));
        $alongside = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))
            ->withRelayState('other')
            ->with('SigAlg', $signed->value('SigAlg'))
            ->with('Signature', $signed->value('Signature'));
        $response = RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE))
            ->withRelayState('state')
            ->with('SigAlg', $signed->value('SigAlg'))
            ->with('Signature', $signed->value('Signature'));

        yield 'the receiver, another AuthnRequest in place of the one signed' => ['receiver, authnRequest()', $inPlace];
        yield 'the receiver, another AuthnRequest and RelayState under the signature' => [
            'receiver, authnRequest()',
            $alongside,
        ];
        yield 'a ReceivedAuthnRequest built by hand, another AuthnRequest in place of the one signed' => [
            'by hand, ReceivedAuthnRequest',
            $inPlace,
        ];
        yield 'a ReceivedAuthnRequest built by hand, another AuthnRequest and RelayState under the signature' => [
            'by hand, ReceivedAuthnRequest',
            $alongside,
        ];
        yield 'the receiver, a LogoutResponse under the signature of an AuthnRequest' => [
            'receiver, logoutMessage()',
            $response,
        ];
        yield 'a ReceivedLogoutResponse built by hand, a LogoutResponse under the signature of an AuthnRequest' => [
            'by hand, ReceivedLogoutResponse',
            $response,
        ];
    }

    /**
     * B-5, section 6.2 step 1, section 8, SAML Bindings §3.5.4
     *
     * @param 'receiver, authnRequest()'|'by hand, ReceivedAuthnRequest'|'receiver, logoutMessage()'|'by hand, ReceivedLogoutResponse'|'receiver, response()'|'by hand, ReceivedResponse' $path
     * @param array<array-key, mixed> $form
     */
    #[Test]
    #[DataProvider('provideFormsWithTheSignatureOfAQueryString')]
    public function itNeverPairsAFormWithADetachedSignature(string $path, array $form): void
    {
        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('SigAlg or Signature in a form is refused: HTTP-POST carries no detached signature (section 8).');

        // When
        match ($path) {
            'receiver, authnRequest()' => self::postReceiver()->authnRequest($form),
            'by hand, ReceivedAuthnRequest' => new ReceivedAuthnRequest($this->formOf($form, Service::SingleSignOn)),
            'receiver, logoutMessage()' => self::postReceiver()->logoutMessage($form),
            'by hand, ReceivedLogoutResponse' => new ReceivedLogoutResponse($this->formOf(
                $form,
                Service::SingleLogout,
            )),
            'receiver, response()' => self::postReceiver()->response($form),
            'by hand, ReceivedResponse' => new ReceivedResponse($this->formOf($form, Service::AssertionConsumer)),
        };
    }

    /**
     * @return iterable<string, array{string, array<array-key, mixed>}>
     */
    public static function provideFormsWithTheSignatureOfAQueryString(): iterable
    {
        $signed = RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE))->withRelayState('state')->signed();
        $signature = [
            ['RelayState', 'state'],
            ['SigAlg', rawurldecode($signed->value('SigAlg'))],
            ['Signature', rawurldecode($signed->value('Signature'))],
        ];
        $request = BrowserForm::posted([
            ['SAMLRequest', base64_encode(self::fixture(self::AUTHN_REQUEST))],
            ...$signature,
        ]);
        $logoutResponse = BrowserForm::posted([
            ['SAMLResponse', base64_encode(self::fixture(self::LOGOUT_RESPONSE))],
            ...$signature,
        ]);
        $response = BrowserForm::posted([
            ['SAMLResponse', base64_encode(self::fixture(self::RESPONSE))],
            ...$signature,
        ]);

        yield 'the receiver, an AuthnRequest' => ['receiver, authnRequest()', $request];
        yield 'a ReceivedAuthnRequest built by hand' => ['by hand, ReceivedAuthnRequest', $request];
        yield 'the receiver, the LogoutResponse the query string signed' => [
            'receiver, logoutMessage()',
            $logoutResponse,
        ];
        yield 'a ReceivedLogoutResponse built by hand, the LogoutResponse the query string signed' => [
            'by hand, ReceivedLogoutResponse',
            $logoutResponse,
        ];
        yield 'the receiver, a Response' => ['receiver, response()', $response];
        yield 'a ReceivedResponse built by hand' => ['by hand, ReceivedResponse', $response];
    }

    /**
     * @param list<string> $types
     */
    #[Test]
    #[TestWith([
        '<?php final class A { private function __construct(public Document $d, private ?DetachedSignature $s) {} }',
        '__construct',
        true,
        ['Document', 'DetachedSignature'],
    ], 'a private constructor')]
    #[TestWith([
        '<?php final class A { public static function of(string $q, \Beffroi\Xml\Core\Loader $l, int $m = 1): self {} }',
        'of',
        false,
        ['string', 'Loader', 'int'],
    ], 'a public factory, a qualified name and a default')]
    #[TestWith([
        '<?php final class A { #[Test] private static function f(Closure $c): void {} }',
        'f',
        true,
        ['Closure'],
    ], 'an attribute before the modifiers')]
    #[TestWith([
        '<?php use function sprintf; final class A { public function f(int $a): void {} }',
        'f',
        false,
        ['int'],
    ], 'an imported function aside')]
    public function itReadsTheParametersOfAFunction(string $source, string $name, bool $private, array $types): void
    {
        // When / Then
        static::assertSame(
            [['file' => 'A.php', 'name' => $name, 'private' => $private, 'types' => $types]],
            $this->functionsOf('A.php', $source),
        );
    }

    /**
     * @param Path $path
     */
    private function validate(string $path, RedirectQuery $query): mixed
    {
        return match ($path) {
            'receiver, authnRequest()' => $this->validateAuthnRequest(
                self::receiver()->authnRequest($query->toString()),
            ),
            'by hand, ReceivedAuthnRequest' => $this->validateAuthnRequest(new ReceivedAuthnRequest(self::reception(
                $query,
                Service::SingleSignOn,
            ))),
            'receiver, logoutMessage()' => $this->validateLogoutResponse(
                self::receiver()->logoutMessage($query->toString()),
            ),
            'by hand, ReceivedLogoutResponse' => $this->validateLogoutResponse(new ReceivedLogoutResponse(self::reception(
                $query,
                Service::SingleLogout,
            ))),
        };
    }

    private function validateAuthnRequest(ReceivedAuthnRequest $received): mixed
    {
        return $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );
    }

    private function validateLogoutResponse(object $received): mixed
    {
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        return $received->validate(
            self::logoutResponseValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::IDP_SLO,
            self::LOGOUT_REQUEST_ID,
        );
    }

    /**
     * @param array<array-key, mixed> $form
     */
    private function formOf(array $form, Service $service): Reception
    {
        return Reception::ofForm($form, $service, SamlLoader::create(), 1_572_864);
    }

    /**
     * @param list<string> $types
     * @param list<string> $among
     */
    private function takesAny(array $types, array $among): bool
    {
        return array_intersect($types, $among) !== [];
    }

    /**
     * @return list<array{file: string, name: string, private: bool, types: list<string>}>
     */
    private function functions(): array
    {
        $directory = dirname(__DIR__, 3) . '/src/saml2-bindings/src';
        $functions = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            static::assertIsString($source);
            $functions = [
                ...$functions,
                ...$this->functionsOf(substr($file->getPathname(), strlen($directory) + 1), $source),
            ];
        }

        return $functions;
    }

    /**
     * @return list<array{file: string, name: string, private: bool, types: list<string>}>
     */
    private function functionsOf(string $file, string $source): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn (#[SensitiveParameter] PhpToken $phpToken): bool => ! $phpToken->isIgnorable(),
        ));
        $functions = [];
        foreach ($tokens as $index => $token) {
            if (! $token->is(T_FUNCTION) || ($tokens[$index - 1] ?? null)?->is(T_USE) === true) {
                continue;
            }
            $functions[] = [
                'file' => $file,
                'name' => $tokens[$index + 1]->text ?? '',
                'private' => $this->isPrivate($tokens, $index),
                'types' => $this->parameterTypes($tokens, $index),
            ];
        }

        return $functions;
    }

    /**
     * @param list<PhpToken> $tokens
     */
    private function isPrivate(array $tokens, int $function): bool
    {
        for ($index = $function - 1; $index >= 0 && $tokens[$index]->is(self::MODIFIERS); --$index) {
            if ($tokens[$index]->is(T_PRIVATE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<PhpToken> $tokens
     *
     * @return list<string>
     */
    private function parameterTypes(array $tokens, int $function): array
    {
        $index = $function;
        while (($tokens[$index] ?? null)?->text !== '(') {
            ++$index;
        }
        $depth = 0;
        $types = [];
        $counter = count($tokens);
        for (; $index < $counter; ++$index) {
            $text = $tokens[$index]->text;
            $depth += match ($text) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };
            if ($depth === 0) {
                break;
            }
            if ($tokens[$index]->is([T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE])) {
                $types[] = $this->shortName($text);
            }
        }

        return $types;
    }

    private function shortName(string $name): string
    {
        $last = strrchr($name, '\\');

        return $last === false ? $name : substr($last, 1);
    }
}
