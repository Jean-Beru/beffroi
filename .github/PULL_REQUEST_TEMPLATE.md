## What

<!-- One paragraph. Link the issue: Closes #… -->

## Specification

<!-- RFC / OpenID sections this change implements or affects, or "none". -->

## Checklist

- [ ] `castor prepare-pr` is clean (ECS, Rector, PHPStan level max, Deptrac, lint) and `castor phpunit` passes
- [ ] Tests name the specification section they verify
- [ ] No new synchronous write, or the exception is listed in `messenger.yaml` with its reason
- [ ] No boolean from a third party is cast, every secret comparison uses `hash_equals()`
- [ ] User-facing strings are translated (`en`, `fr`)
- [ ] Security defaults are untouched, or the named exception is bounded and documented
