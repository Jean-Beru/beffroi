<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\PhpStan;

use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FunctionCallableNode;
use PHPStan\Node\MethodCallableNode;
use PHPStan\Node\StaticMethodCallableNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;

/**
 * Section 8
 *
 * @template TNode of FunctionCallableNode|MethodCallableNode|StaticMethodCallableNode
 *
 * @implements Rule<TNode>
 */
final readonly class BannedCallablesRule implements Rule
{
    /**
     * @param class-string<TNode> $nodeType
     */
    public function __construct(
        private BannedCallsRule $calls,
        private string $nodeType,
    ) {
    }

    public function getNodeType(): string
    {
        return $this->nodeType;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        return $this->calls->processNode($node->getOriginalNode(), $scope);
    }
}
