<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\PhpStan\Fixture;

/*
 * Every form section 8 of src/saml/spec/saml.md bans, one line each, and the lines that must pass. It is analysed by
 * `castor phpstan-saml-rules` under .ci-tools/phpstan-saml-rules.neon, which is the rules of .ci-tools/phpstan-saml.neon
 * pointed at this file alone, and by no other analysis, nor by the suite, nor by the formatter or Rector: it is not
 * code, it is the question put to the rules.
 *
 * A line that ends in `// error: <message>` must be refused by the rules of section 8 (identifier beffroi.bannedCall)
 * with that message, one marker for each message; a line with none must not be refused by them at all. The task fails
 * on a refusal missing and on a refusal nobody expected, so that a rule that stops firing, a rule that starts firing on
 * what it let through and a line that moved are all red. What PHPStan's other rules say of this file (an unused
 * variable, a missing generic type) is not the question and is not read.
 */

final class Validator
{
    public function validateAuthenticatedByBinding(): void
    {
    }

    /**
     * @param array<mixed> $data
     */
    public function __unserialize(array $data): void
    {
    }

    public function bind(): void
    {
    }

    public function call(): void
    {
    }

    /**
     * @return \ReflectionClass<object>
     */
    public function reflector(): \ReflectionClass
    {
        throw new \LogicException('Never called.');
    }
}

/**
 * @extends \ReflectionClass<object>
 */
final class ExtendingReflection extends \ReflectionClass
{
}

final class BannedForms
{
    /**
     * @param class-string<\ReflectionClass<object>> $reflectionClass
     */
    public function banned(
        Validator $validator,
        ?Validator $maybe,
        \Closure $closure,
        \ReflectionProperty $property,
        string $name,
        string $method,
        string $class,
        string $reflectionClass,
        callable $callable,
        array $unread,
    ): void {
        // the methods banned on any receiver
        $validator->validateAuthenticatedByBinding(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $validator->VALIDATEAUTHENTICATEDBYBINDING(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $maybe?->validateAuthenticatedByBinding(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $validator->__unserialize([]); // error: __unserialize() is never called: section 8 of the specification bans it.
        Validator::validateAuthenticatedByBinding(); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.

        // the functions banned
        unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        \unserialize(''); // error: unserialize() is never called: section 8 of the specification bans it.
        \UNSERIALIZE(''); // error: unserialize() is never called: section 8 of the specification bans it.

        // the methods of Closure, statically and on an instance
        \Closure::bind($closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        $closure->bindTo(null); // error: Closure::bindTo() is never called: section 8 of the specification bans it.
        $closure->call($validator); // error: Closure::call() is never called: section 8 of the specification bans it.

        // Reflection: instantiated, called statically, a method of an object of one, and what extends it
        $reflected = new \ReflectionClass(Validator::class); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionObject($validator); // error: ReflectionObject is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionMethod($validator, 'bind'); // error: ReflectionMethod is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionEnum(Validator::class); // error: ReflectionEnum is never used: section 8 of the specification bans Reflection.
        $reflected = new \ReflectionFunction($closure); // error: ReflectionFunction is never used: section 8 of the specification bans Reflection.
        $reflected = new \reflectionclass(Validator::class); // error: reflectionclass is never used: section 8 of the specification bans Reflection.
        \Reflection::getModifierNames(1); // error: Reflection is never used: section 8 of the specification bans Reflection.
        $property->setValue($validator, 1); // error: ReflectionProperty is never used: section 8 of the specification bans Reflection.
        $validator->reflector()->getName(); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new ExtendingReflection(Validator::class); // error: Beffroi\Saml\Tests\PhpStan\Fixture\ExtendingReflection is never used: section 8 of the specification bans Reflection.
        $reflected = new class(Validator::class) extends \ReflectionClass {}; // error: ReflectionClass is never used: section 8 of the specification bans Reflection.

        // a class given as a value
        $reflected = new $reflectionClass(Validator::class); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new ('ReflectionClass')(Validator::class); // error: ReflectionClass is never used: section 8 of the specification bans Reflection.
        $reflected = new $class(); // error: An instantiation whose class PHPStan cannot read escapes the review: name the class.

        // a function, a method or a class given as a constant string or array, called
        $constant = 'unserialize';
        $constant(''); // error: unserialize() is never called: section 8 of the specification bans it.
        $constant = 'Closure::bind';
        $constant($closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        [$validator, 'validateAuthenticatedByBinding'](); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        [$closure, 'bindTo'](null); // error: Closure::bindTo() is never called: section 8 of the specification bans it.
        ['Closure', 'bind']($closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.

        // the same, as an argument of any call
        array_map('unserialize', ['']); // error: unserialize() is never called: section 8 of the specification bans it.
        call_user_func('unserialize', ''); // error: unserialize() is never called: section 8 of the specification bans it.
        \Closure::fromCallable('unserialize'); // error: unserialize() is never called: section 8 of the specification bans it.
        array_map([$validator, 'validateAuthenticatedByBinding'], []); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        call_user_func('Closure::bind', $closure, null); // error: Closure::bind() is never called: section 8 of the specification bans it.
        array_map([\Reflection::class, 'getModifierNames'], [1]); // error: Reflection is never used: section 8 of the specification bans Reflection.

        // a first-class callable
        $first = unserialize(...); // error: unserialize() is never called: section 8 of the specification bans it.
        $first = $validator->validateAuthenticatedByBinding(...); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $first = $validator->__unserialize(...); // error: __unserialize() is never called: section 8 of the specification bans it.
        $first = \Closure::bind(...); // error: Closure::bind() is never called: section 8 of the specification bans it.
        $first = Validator::validateAuthenticatedByBinding(...); // error: validateAuthenticatedByBinding() is never called: section 8 of the specification bans it.
        $first = $closure->bindTo(...); // error: Closure::bindTo() is never called: section 8 of the specification bans it.

        // what PHPStan cannot read
        $name(); // error: A call whose function PHPStan cannot read escapes the review: name the function.
        $validator->$method(); // error: A call whose method PHPStan cannot read escapes the review: name the method.
        $unread(); // error: A call whose function PHPStan cannot read escapes the review: name the function.
        $callable(); // error: A call whose function PHPStan cannot read escapes the review: name the function.
    }

    /**
     * What section 8 lets through: the lines below must not be refused.
     */
    public function witness(Validator $validator, \Closure $closure, string $text): void
    {
        $validator->bind();
        $validator->call();
        $closure();
        $closure->__invoke();
        strtoupper($text);
        array_map('strtoupper', [$text]);
        call_user_func('strtolower', $text);
        \Closure::fromCallable('strlen');
        $witnessed = strlen(...);
        $witnessed = $validator->bind(...);
        $witnessed = \Closure::fromCallable($closure);
        $witnessed = json_decode($text);
        $witnessed = serialize($text);
        $witnessed = new \ReflectionException();
        $witnessed = new \stdClass();
    }
}
