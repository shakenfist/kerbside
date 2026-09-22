#!/bin/bash

# Assert that no sentence in docs/use-cases/ claims the
# Kerbside-to-hypervisor ("backend") leg is TLS'd or certificate-pinned
# without naming the condition under which that is true.
#
# The leg is conditional in three ways, all in
# rust/kerbside-proxy/src/backend.rs. The proxy dials the insecure port
# first and escalates to TLS only inside
# `if is_need_secured(&first_err) && target.secure_port != 0` (:85-115),
# so TLS happens when the hypervisor rejects plaintext by asking for a
# secure connection and a secure port is configured to escalate to. An
# empty host_subject maps to None (:206), so the subject is pinned only
# when the source supplied one -- an empty one silently disables
# verification. An empty ca_cert maps to None too, which leaves the
# target checked against the public web trust store that an internal
# certificate will not satisfy.
#
# Four consecutive phases of PLAN-use-case-docs.md stated that leg more
# strongly than the code supports, and three of the four were caught by
# review rather than by writing. This script is the tripwire for the
# fifth: it fails when a *new* unconditional claim appears in a block of
# its own. It is not a proof that the prose is right.
#
# The limit, concretely. It works on blocks -- a bullet, a paragraph or
# a table row -- and a block naming its condition anywhere satisfies
# it, so a claim mixed into a block that conditions something else
# passes. The version of docs/use-cases/shakenfist.md that said
# Kerbside "pins the certificate subject the node publishes" -- false
# when the node publishes none -- passes this check, because the same
# bullet correctly conditions the escalation on NEED_SECURED. Making
# the test per-sentence instead was tried and is worse: it flags the
# negative claim at openstack.md:45, a cross-reference at :310 and a
# continuation sentence whose condition sits in the sentence before
# it. Read the prose; this only makes the careless case loud.
#
# Fenced blocks are skipped: the mermaid diagrams label an edge with the
# outcome of a flow whose condition the surrounding prose states, and
# there is no room in a diagram label to restate it.

set -e

cd "$(dirname "$0")/.."

python3 - docs/use-cases/*.md <<'PY'
import re
import sys

# A sentence makes a claim when it is about the backend side of
# Kerbside, asserts something with a finite verb, and that something is
# pinning or transport security. All three are needed: "both the
# plaintext and TLS ports" is reachability rather than a claim, and
# "the full detail of ... backend pinning" is a pointer to a document.
BACKEND = re.compile(
    r'\b(?:backend|hypervisor|hypervisors|node|nodes|target|targets)\b', re.I)
ASSERTS = re.compile(
    r'\b(?:is|are|was|were|be|been|does|do|did|will|can|must|has|have|'
    r'pins|verifies|escalates|relays|refuses|fails|happens|enforces|'
    r'encrypts|terminates|dials|connects|retries|checks)\b', re.I)
PIN = re.compile(r'\bpin(?:s|ned|ning)?\b', re.I)
CRYPTO = re.compile(
    r"\b(?:escalat\w+|encrypt\w+|verif\w+)\b|\bTLS'd\b|\bover TLS\b", re.I)

# Words which name a condition. Any one of them in the block the
# sentence belongs to is enough.
CONDITIONAL = re.compile(
    r'\b(?:when|where|whether|if|unless|only|optional|optionally|absent|'
    r'without|none|never|depends|requires?|demands?|suppl(?:y|ies|ied)|'
    r'configured|unpinned|untested|should)\b', re.I)

BULLET = re.compile(r'^\s*[-*+] ')


def blocks(path):
    """Yield [(line number, text), ...] for each block of a markdown file.

    A block is a bullet item with its continuation lines, a table row, or
    a run of paragraph lines. Fenced code and headings are skipped.
    """
    block = []
    fenced = False
    for number, line in enumerate(open(path).readlines(), start=1):
        stripped = line.strip()
        if stripped.startswith('```'):
            fenced = not fenced
            stripped = ''
        if fenced or stripped.startswith('#'):
            stripped = ''
        starts = (
            not stripped
            or stripped.startswith('|')
            or BULLET.match(line)
            or (block and block[-1][1].startswith('|')))
        if starts and block:
            yield block
            block = []
        if stripped:
            block.append((number, stripped))
    if block:
        yield block


def sentences(block):
    """Yield (line number, sentence) pairs for one block."""
    text = ''
    offsets = []
    for number, line in block:
        offsets.append((len(text), number))
        text += line + ' '
    for match in re.finditer(r'[^.!?]+[.!?]*', text):
        sentence = match.group(0).strip()
        if not sentence:
            continue
        number = offsets[0][1]
        for offset, candidate in offsets:
            if offset <= match.start():
                number = candidate
        yield number, sentence


failures = 0
for path in sys.argv[1:]:
    for block in blocks(path):
        joined = ' '.join(line for _, line in block)
        if CONDITIONAL.search(joined):
            continue
        for number, sentence in sentences(block):
            if not (BACKEND.search(sentence) and ASSERTS.search(sentence)):
                continue
            if PIN.search(sentence) or CRYPTO.search(sentence):
                print('%s:%d: backend TLS or pinning is claimed with no '
                      'condition named:' % (path, number), file=sys.stderr)
                print('  %s' % sentence, file=sys.stderr)
                failures += 1

if failures:
    print('', file=sys.stderr)
    print('Say when the claim holds: TLS happens when the hypervisor '
          'rejects', file=sys.stderr)
    print('plaintext and a secure port is configured, the subject is '
          'pinned when', file=sys.stderr)
    print('the source supplied one, and a private CA has to be supplied '
          'or the', file=sys.stderr)
    print('handshake fails. See rust/kerbside-proxy/src/backend.rs.',
          file=sys.stderr)
    sys.exit(1)

print('No unconditional backend TLS or pinning claims in docs/use-cases/.')
PY
