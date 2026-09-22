#!/usr/bin/env python3

"""Fail when documentation claims the backend leg is TLS'd or pinned
without naming the condition under which that is true.

The Kerbside-to-hypervisor ("backend") leg is conditional in three
ways, all in rust/kerbside-proxy/src/backend.rs. The proxy dials the
insecure port first and escalates to TLS only inside
`if is_need_secured(&first_err) && target.secure_port != 0` (:85-115),
so TLS happens when the hypervisor rejects plaintext by asking for a
secure connection and there is a secure port to escalate to. An empty
host_subject maps to None (:206), so the subject is pinned only when
the source supplied one -- an empty one silently disables
verification. An empty ca_cert maps to None too, which leaves the
target checked against the public web trust store that an internal
certificate will not satisfy.

Five consecutive phases of PLAN-use-case-docs.md stated that leg more
strongly than the code supports, and three of the five were caught by
review rather than by writing. This is the tripwire for the sixth. It
is not a proof that the prose is right.

The limit, concretely. It works on blocks -- a bullet, a paragraph or
a table row -- and a block naming its condition anywhere satisfies it,
so a claim mixed into a block that conditions something else passes.
The version of docs/use-cases/shakenfist.md that said Kerbside "pins
the certificate subject the node publishes" -- false when the node
publishes none -- passes this check, because the same bullet correctly
conditions the escalation on NEED_SECURED. Making the test
per-sentence instead was tried and is worse: it flags the negative
claim at openstack.md:45, a cross-reference at :310 and a continuation
sentence whose condition sits in the sentence before it.

The conditional vocabulary is deliberately narrow, because a word that
is not a condition marker exempts every block it appears in. Review of
pull request #469 found `configured` doing exactly that: "Kerbside
connects to the configured hypervisor over TLS and pins the
certificate subject it was given" names no condition at all and was
passing, and these pages say "configured cloud" and "configured
source" constantly. `should` and `none` went with it for the same
reason. Do not add a word here without appending a case to
kerbside/tests/unit/test_check_backend_tls_claims.py that fails
without it.

Fenced blocks are skipped: the mermaid diagrams label an edge with the
outcome of a flow whose condition the surrounding prose states, and
there is no room in a diagram label to restate it.
"""

import glob
import os
import re
import sys


# A sentence makes a claim when it is about the backend side of
# Kerbside, asserts something, and that something is pinning or
# transport security. All three are needed: "both the plaintext and TLS
# ports" is reachability rather than a claim, and matches neither PIN
# nor CRYPTO.
#
# ASSERTS is weaker than it looks, and the test file says so: a
# cross-reference like "the full detail of backend pinning is in the
# proxy architecture reference" satisfies all three conjuncts on `is`.
# What spares that sentence is the block it sits in, not this pattern.
# `pinned` is here as well as in PIN because the Use Cases table in
# docs/index.md describes a page in a noun phrase with no finite verb
# at all -- "host-subject pinned TLS to the hypervisor" -- which is how
# an unconditional claim survived two lines from the page that had
# just qualified it.
BACKEND = re.compile(
    r'\b(?:backend|hypervisor|hypervisors|node|nodes|target|targets)\b',
    re.I)
ASSERTS = re.compile(
    r'\b(?:is|are|was|were|be|been|does|do|did|will|can|must|has|have|'
    r'pins|verifies|escalates|relays|refuses|fails|happens|enforces|'
    r'encrypts|terminates|dials|connects|retries|checks|pinned)\b', re.I)
PIN = re.compile(r'\bpin(?:s|ned|ning)?\b', re.I)
CRYPTO = re.compile(
    r"\b(?:escalat\w+|encrypt\w+|verif\w+)\b|\bTLS'd\b|\bover TLS\b", re.I)

# Words which name a condition. Any one of them in the block the
# sentence belongs to is enough, which is why the list is short: see
# the module docstring before adding to it.
CONDITIONAL = re.compile(
    r'\b(?:when|where|whether|if|unless|only|optional|optionally|absent|'
    r'without|never|depends|requires?|demands?|suppl(?:y|ies|ied)|'
    r'unpinned|untested)\b', re.I)

BULLET = re.compile(r'^\s*[-*+] ')

# Markdown emphasis runs, stripped before sentences are split so that
# the period in "**The backend leg is pinned.**" is not hidden behind a
# trailing marker. Underscore emphasis is deliberately not stripped:
# these pages are full of snake_case identifiers, and removing the
# underscores turns host_subject into hostsubject in both the matching
# and the reported text.
EMPHASIS = re.compile(r'\*{1,3}|`')

# A sentence ends at a terminator followed by whitespace or the end of
# the text. Splitting on the terminator alone ends a sentence inside
# "backend.rs" and "ovirt.md", which both truncates the reported text
# and can strand the two halves of one claim in separate fragments,
# where neither half matches on its own.
SENTENCE_END = re.compile(r'(?<=[.!?])\s+')

# Documentation this runs over: the per-deployment pages, plus the
# Use Cases table in docs/index.md, whose scenario cells describe those
# same pages and had drifted the same way (review of #469 found the
# oVirt row claiming "host-subject pinned TLS to the hypervisor" two
# lines from the page where that claim had just been qualified).
#
# Deliberately not every file under docs/. That was tried, and the
# other seventeen produce six hits of which one is a real claim: a
# filename (verify-terminate-live.sh) matches the crypto vocabulary, a
# task being "pinned forever" matches the pinning vocabulary, and a
# list of Target fields matches both. Silencing five false positives by
# tuning the regexes is how a guard stops catching anything, which is
# the failure this check already exists to prevent. The one real hit,
# docs/proxy-architecture.md:62 on the Shaken Fist scrape-time subject,
# is tracked as issue #472 rather than left to a plan section.
DOC_PATHS = ('docs/use-cases/*.md', 'docs/index.md')


def repository_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_paths():
    """The documentation files this check covers.

    Resolved against the repository rather than the working directory,
    and returned relative to it. Globbing the bare patterns returned []
    from anywhere but the root, which a unit test cannot rely on.
    """
    root = repository_root()
    paths = []
    for pattern in DOC_PATHS:
        paths.extend(glob.glob(os.path.join(root, pattern)))
    return sorted(os.path.relpath(p, root) for p in paths)


def blocks(path):
    """Yield [(line number, text), ...] for each block of a markdown file.

    A block is a bullet item with its continuation lines, a table row, or
    a run of paragraph lines. Fenced code and headings are skipped.
    """
    block = []
    fenced = False
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith('```'):
            fenced = not fenced
            stripped = ''
        if fenced:
            stripped = ''
        # A heading is its own block. Blanking it, as this did until
        # review of #469 found it, means "## The backend leg is pinned"
        # is never examined -- a hole that was not among the limits the
        # docstring states, which is worse than a stated one.
        if stripped.startswith('#'):
            if block:
                yield block
            yield [(number, stripped)]
            block = []
            continue
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
        text += EMPHASIS.sub('', line) + ' '

    start = 0
    for part in SENTENCE_END.split(text):
        offset = text.index(part, start) if part else start
        sentence = part.strip()
        start = offset + len(part)
        if not sentence:
            continue
        number = offsets[0][1]
        for candidate_offset, candidate in offsets:
            if candidate_offset <= offset:
                number = candidate
        yield number, sentence


def claims(path):
    """Yield (line number, sentence) once per offending block.

    Per block rather than per sentence, because the conditional
    exemption is per block: a bullet whose bold lead-in states the
    claim and whose body expands it is one thing to fix, and reporting
    it twice only inflates the count.
    """
    for block in blocks(path):
        joined = ' '.join(line for _, line in block)
        if CONDITIONAL.search(joined):
            continue
        for number, sentence in sentences(block):
            if not (BACKEND.search(sentence) and ASSERTS.search(sentence)):
                continue
            if PIN.search(sentence) or CRYPTO.search(sentence):
                yield number, sentence
                break


def main(paths=None):
    root = repository_root()
    if not paths:
        paths = default_paths()

    failures = 0
    for path in paths:
        for number, sentence in claims(os.path.join(root, path)):
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
        print('the source supplied one, and a private CA has to be '
              'supplied or the', file=sys.stderr)
        print('handshake fails. See rust/kerbside-proxy/src/backend.rs.',
              file=sys.stderr)
        return 1

    print('No unconditional backend TLS or pinning claims in %d '
          'documentation files.' % len(paths))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
