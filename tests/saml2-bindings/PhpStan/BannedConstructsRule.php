<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\PhpStan;

use function array_all;
use function date_parse;
use function in_array;
use function is_int;
use function is_string;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Expr\BinaryOp\NotEqual;
use PhpParser\Node\Expr\Cast\Bool_;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Switch_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\Type\Constant\ConstantStringType;
use function sprintf;
use function strtolower;

/**
 * Section 8, model.md section 8, M-6, M-8, B-13, section 6.8
 *
 * @implements Rule<Node>
 */
final readonly class BannedConstructsRule implements Rule
{
    private const array CLOCK_CLASSES = ['datetime', 'datetimeimmutable'];

    /**
     * @param list<string> $variables names without their $
     */
    public function __construct(
        private array $variables,
    ) {
    }

    public function getNodeType(): string
    {
        return Node::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $message = match (true) {
            $node instanceof Equal => '== compares loosely: section 8 of the specification bans it, === compares.',
            $node instanceof NotEqual => '!= compares loosely: section 8 of the specification bans it, !== compares.',
            $node instanceof Switch_ => 'switch compares loosely: section 8 of the specification bans it, match compares.',
            $node instanceof Bool_ => '(bool) casts: section 8 of the specification bans it, a boolean is compared as a string.',
            $node instanceof New_ => $this->readsTheClock($node, $scope),
            $node instanceof Variable => $this->superglobal($node),
            default => null,
        };
        if ($message === null) {
            return [];
        }

        return [RuleErrorBuilder::message($message)->identifier('beffroi.bannedConstruct')->nonIgnorable()->build()];
    }

    private function superglobal(Variable $node): ?string
    {
        if (! is_string($node->name) || ! in_array($node->name, $this->variables, true)) {
            return null;
        }

        return sprintf(
            '$%s is never read: section 8 of the specification bans the superglobals, the package takes strings and arrays.',
            $node->name,
        );
    }

    private function readsTheClock(New_ $node, Scope $scope): ?string
    {
        if (! $node->class instanceof Name) {
            return null;
        }
        $class = $scope->resolveName($node->class);
        if (! in_array(strtolower($class), self::CLOCK_CLASSES, true)) {
            return null;
        }
        $time = $this->timeArgument($node);
        if ($time instanceof Arg && $this->isExplicit($time, $scope)) {
            return null;
        }

        return sprintf(
            'new \\%s() without an explicit UTC time reads the clock of the machine: section 8 of the specification bans it, the clock port is the time.',
            $class,
        );
    }

    private function timeArgument(New_ $node): ?Arg
    {
        foreach ($node->getArgs() as $position => $argument) {
            if ($argument->unpack) {
                return null;
            }
            if ($argument->name === null ? $position === 0 : $argument->name->toString() === 'datetime') {
                return $argument;
            }
        }

        return null;
    }

    private function isExplicit(Arg $time, Scope $scope): bool
    {
        $type = $scope->getType($time->value);
        $constants = $type->getConstantStrings();
        if ($constants === []) {
            return $type->isString()->yes();
        }

        return array_all(
            $constants,
            static fn (ConstantStringType $constant): bool => self::isAbsoluteUtc($constant->getValue()),
        );
    }

    private static function isAbsoluteUtc(string $time): bool
    {
        $parsed = date_parse($time);
        if ($parsed['error_count'] !== 0 || ($parsed['relative'] ?? null) !== null) {
            return false;
        }
        foreach (['year', 'month', 'day', 'hour', 'minute', 'second'] as $field) {
            if (! is_int($parsed[$field])) {
                return false;
            }
        }
        if ($parsed['is_localtime'] !== true) {
            return false;
        }

        if (($parsed['tz_id'] ?? null) === 'UTC') {
            return true;
        }

        return ($parsed['zone'] ?? null) === 0 && ($parsed['is_dst'] ?? null) === false;
    }
}
