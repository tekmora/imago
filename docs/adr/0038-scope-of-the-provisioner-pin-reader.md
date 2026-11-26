# 38. Scope of the Provisioner Pin Reader

Date: 2026-11-26

## Status

Accepted.

## Context

The pin consumption test checks that the Packer environment pins have provisioner reads. Bash can select command names, options, operators and code at runtime. A parse tree alone cannot establish which pins those constructs read.

## Decision

Use the [pin reader](../../tests/test_version_pins_consumed.py) as a tripwire for its listed read shapes and constructs. Refuse other pin mentions by name. Count an all-members array expansion only when the source bytes inside the brackets are exactly `@` or `*`.

Refuse arithmetic, indirection, dynamic variable names and dynamic code in the listed constructs. Require literal command names, including after the listed prefixes, and literal words in the option and operator positions that select names or code. Refuse the `eval` builtin and extended glob patterns regardless of the names they contain.

Refuse unquoted parameter, command, arithmetic and process expansions in simple command words, loop word lists, array literal elements and non-assignment declaration words. Bash can split unquoted expansions into run-time words in these positions. Refuse `env -S` and `env --split-string`, including clustered short options and literal values, because `env` splits and expands the value itself.

Alias and function shadowing of command names are outside the tripwire's scope.

## Consequences

The check reports refusals with their file, line, construct and syntax tree path. A provisioner that uses a refused shape fails the pin consumption check. A script path held in a variable follows `--` when it is passed to `sh`, as in `52-k3s-runtime.sh`. The tripwire provides no proof of execution or complete Bash semantics.
