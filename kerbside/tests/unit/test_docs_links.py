import collections
import os
import re
import shutil
import subprocess
import tempfile

import testtools


def _repo_root():
    """Return the repository root, or None outside a checkout.

    Markdown is repository data, not package data: nothing under docs/
    is beneath a package directory, so setuptools_scm's file finder
    does not contribute it and no wheel contains it. Walk up from
    __file__ for the same reason test_demo_stack.py does.
    """
    path = os.path.dirname(os.path.abspath(__file__))
    while path != '/':
        # os.path.exists, not os.path.isdir: in a git worktree .git is
        # a file holding a gitdir pointer, and this repository is
        # routinely developed in worktrees.
        if os.path.exists(os.path.join(path, '.git')):
            return path
        path = os.path.dirname(path)
    return None


class MarkdownLinkTestCase(testtools.TestCase):
    """Every relative markdown link between our own .md files resolves.

    This is the markdown counterpart of StaticAssetReferenceTestCase in
    test_api_html.py, and it exists for the same reason: nothing but a
    human clicking the link would otherwise notice that a document
    points at a file which is not there. On GitHub a dangling relative
    link renders as live and 404s on click.

    The case that prompted it is the plan directory. `docs/plans/`
    cross-references heavily -- a master plan links each of its phase
    files, and index.md links all of them again -- and the convention
    is that a phase file lands in the same commit as the row which
    references it. A phase row written ahead of its file breaks both
    links at once, and PR #366 did exactly that.

    Anchors are checked too, against the headings of the file they
    point into, because `docs/index.md#use-cases` is linked from both
    README.md and ARCHITECTURE.md and renaming that heading would
    break two curated entry points with nothing noticing.

    Deliberately not a markdown parser. The invariant is about the link
    targets the file actually emits, and a regex over the source cannot
    be fooled into resolving a path a reader would not see.
    """

    # ](target) with no whitespace in the target. Reference-style links
    # and bare autolinks are not matched: neither appears in this tree,
    # and a matcher for them would be guessing at syntax we do not use.
    LINK_RE = re.compile(r'\]\(([^)\s]+?)\)')

    # An absolute link into this repository's own GitHub blob view. The
    # ref matters: `develop` names the tree this test can see, while a
    # pinned sha names frozen history -- retired plans are linked that
    # way precisely because their files are gone -- so only the first
    # is checkable here.
    SELF_BLOB_RE = re.compile(
        r'^https://github\.com/shakenfist/kerbside/blob/([^/]+)/([^#?]+)'
        r'(?:#(.*))?$')
    DEFAULT_BRANCH = 'develop'

    # A setext-free tree, so one form of heading. Trailing hashes are
    # decoration and are not part of the rendered text. No guard holds
    # the tree to that -- `---` is ambiguous with a table rule and with
    # YAML front matter, so a detector for it would have to guess -- so
    # if a setext heading is ever written, a correct link into it is
    # reported as dangling, with the file's other anchors listed and no
    # mention of the real cause. That is the symptom to read backwards
    # from.
    HEADING_RE = re.compile(r'^(#{1,6})\s+(.*?)\s*#*$')
    FENCE_RE = re.compile(r'^\s*(?:```|~~~)')

    # The rendered text of a heading, as far as the slug is concerned:
    # a link becomes its text, inline HTML vanishes along with the code
    # ticks, and emphasis markers are not part of what GitHub slugs.
    # Underscores survive, because GitHub keeps them --
    # `sf_console_token_audience` slugs to itself, and so do the dozen
    # `FILE_XFER_START (ID 10)` headings in docs/spice/. That is also
    # why `_` is not an emphasis marker here: telling `_italic_` from
    # an identifier needs CommonMark's flanking rules, no heading in
    # the tree uses `_` for emphasis, and stripping it everywhere
    # would corrupt the headings which do have it.
    INLINE_LINK_RE = re.compile(r'\[([^\]]*)\]\([^)]*\)')
    INLINE_HTML_RE = re.compile(r'<[^>]+>')
    EMPHASIS_RE = re.compile(r'[*~]')
    PUNCTUATION_RE = re.compile(r'[^\w\- ]', re.UNICODE)

    @classmethod
    def _without_inline_html(cls, text):
        """Drop HTML tags, and the code ticks, but not what a tick quotes.

        A code span's contents are literal text that GitHub slugs, so
        `` `<title>` `` keeps its angle brackets long enough for the
        punctuation pass to drop them and leave `title`; a real tag
        contributes no text at all. Splitting on the ticks keeps the
        two apart -- odd segments are inside a code span -- and the
        join drops the ticks themselves.
        """
        return ''.join(
            part if n % 2 else cls.INLINE_HTML_RE.sub('', part)
            for n, part in enumerate(text.split('`')))

    @classmethod
    def _slug(cls, heading):
        """GitHub's anchor for a heading, before duplicate suffixing.

        Lowercase, punctuation other than hyphens and underscores
        dropped, each space to a hyphen. Matches github-slugger
        closely enough for the headings this tree has; the test that
        proves it is that every anchor the tree links resolves.
        """
        text = cls.INLINE_LINK_RE.sub(r'\1', heading)
        text = cls._without_inline_html(text)
        text = cls.EMPHASIS_RE.sub('', text)
        text = cls.PUNCTUATION_RE.sub('', text.lower())
        return text.strip().replace(' ', '-')

    @classmethod
    def _anchors(cls, path):
        """Every anchor a reader can reach in one markdown file.

        Fenced blocks are skipped: a `# comment` in a shell sample is
        not a heading, and this tree is full of them. Duplicates take
        GitHub's `-1`, `-2` suffixes on the later occurrences.
        """
        anchors = set()
        seen = {}
        in_fence = False
        with open(path, encoding='utf-8') as f:
            for line in f:
                if cls.FENCE_RE.match(line):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                m = cls.HEADING_RE.match(line.rstrip('\n'))
                if not m:
                    continue
                slug = cls._slug(m.group(2))
                if not slug:
                    continue
                n = seen.get(slug, 0)
                seen[slug] = n + 1
                anchors.add(slug if n == 0 else '%s-%d' % (slug, n))
        return anchors

    def _tempdir(self):
        """A directory removed when the test ends.

        tempfile with addCleanup, which is what every other unit test
        in this tree uses (test_rpc.py, test_main.py, test_demo_token.py
        among them). `fixtures` is not in pyproject.toml's test extra,
        so an import of it here would make this module's importability
        depend on whatever else the environment happened to install.
        """
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def _markdown_files(self, root):
        """Tracked .md files, so a developer's scratch notes are exempt."""
        try:
            out = subprocess.check_output(
                ['git', 'ls-files', '-z', '*.md'], cwd=root, text=True)
        except (OSError, subprocess.CalledProcessError) as e:
            raise self.skipException('cannot list tracked files: %s' % e)
        return [f for f in out.split('\0') if f]

    def test_anchors_follow_githubs_slug_rules(self):
        """The slug rules the anchor check above depends on.

        Written as a fixture rather than against the tree, because the
        tree is not obliged to keep an example of each rule, and the
        check is only as good as these: a slug computed differently
        from GitHub's either passes a link a reader cannot follow, or
        fails one they can.
        """
        fixture = os.path.join(self._tempdir(), 'headings.md')
        with open(fixture, 'w', encoding='utf-8') as f:
            f.write(
                '# Kerbside Documentation\n'
                '## Example sources.yaml\n'
                '## The `kerbside` role\n'
                '## **Bold** and *italic*\n'
                '## [A link](somewhere.md)\n'
                '## sf_console_token_audience\n'
                '## Ports (and their numbers)\n'
                '### `ticket-valid-until=<unix-ts>`\n'
                '## Hard <br/>break\n'
                '## Repeated\n'
                '## Repeated\n'
                '## Repeated\n'
                '```sh\n'
                '# Not a heading, a shell comment\n'
                '```\n'
                '## Trailing hashes ##\n')

        self.assertEqual(
            set([
                'kerbside-documentation',
                # The dot goes, as punctuation, so does the paren pair.
                'example-sourcesyaml',
                'ports-and-their-numbers',
                # Code ticks and emphasis are not part of the text.
                'the-kerbside-role',
                'bold-and-italic',
                # A link slugs as its text, not its target.
                'a-link',
                # An underscore is a word character and survives.
                'sf_console_token_audience',
                # Angle brackets inside a code span are text GitHub
                # slugs, so the punctuation pass drops them rather
                # than the tag matcher eating the whole span.
                'ticket-valid-untilunix-ts',
                # A real tag contributes no text.
                'hard-break',
                # Later duplicates take a suffix; the first does not.
                'repeated', 'repeated-1', 'repeated-2',
                'trailing-hashes',
            ]),
            self._anchors(fixture))

    def _classify(self, relpath, target, tally):
        """Where a link points, or None with the reason tallied.

        Returns a (repository-relative path, anchor or None, class)
        triple for every link this test can check on disk, and None for
        the rest.
        Every link lands in exactly one bucket of the tally, which is
        what the totals below are asserted against: a silent skip is
        how the anchor gap arose in the first place (#490), so a class
        of link cannot be dropped here without the count moving.
        """
        if target.startswith('mailto:'):
            tally['mailto'] += 1
            return None

        if target.startswith('#'):
            # An anchor into the file it is written in.
            tally['in_page'] += 1
            return relpath, target[1:], 'in_page'

        m = self.SELF_BLOB_RE.match(target)
        if m:
            ref, path, anchor = m.groups()
            if ref != self.DEFAULT_BRANCH:
                # A pinned sha, which names a tree this checkout is not.
                # Retired plans are linked that way on purpose.
                tally['pinned'] += 1
                return None
            if not path.endswith('.md'):
                # A blob link into source, which an `#L10` line anchor
                # makes the natural shape of. The file is still checked,
                # but the fragment is not a heading slug and the target
                # has no headings to compare it with: `_anchors` over a
                # .py file reads every `# comment` as one.
                tally['self_absolute_source'] += 1
                return path, None, 'self_absolute_source'
            tally['self_absolute'] += 1
            return path, anchor, 'self_absolute'

        if '://' in target:
            # Somebody else's site. That needs a network and a link
            # checker; this test is about the tree on disk.
            tally['external'] += 1
            return None

        path, _, anchor = target.partition('#')
        path = path.split('?')[0]
        if not path.endswith('.md'):
            # A directory or an image is a different invariant with
            # different failure modes.
            tally['not_markdown'] += 1
            return None

        tally['relative'] += 1
        return (os.path.normpath(os.path.join(os.path.dirname(relpath),
                                              path)),
                anchor or None, 'relative')

    def _check_links(self, root, files):
        """Resolve every link in `files`, each read relative to `root`.

        Returns the complaints and the tally rather than asserting on
        them, and takes the tree to walk rather than finding it: that
        is what lets the negative test below run this over a tree it
        built itself, and so prove that a bad link is reported, not
        only that this tree has none.
        """
        tally = collections.Counter()
        anchors = {}
        dangling = []
        for relpath in files:
            source = os.path.join(root, relpath)
            with open(source, encoding='utf-8') as f:
                body = f.read()

            for target in self.LINK_RE.findall(body):
                tally['matched'] += 1
                where = self._classify(relpath, target, tally)
                if where is None:
                    continue
                path, anchor, kind = where

                resolved = os.path.join(root, path)
                if not os.path.isfile(resolved):
                    dangling.append(
                        '%s links to %s, which does not resolve (looked '
                        'for %s)' % (relpath, target, path))
                    continue

                if not anchor:
                    continue

                tally['anchors_' + kind] += 1
                if path not in anchors:
                    anchors[path] = self._anchors(resolved)
                if anchor in anchors[path]:
                    continue

                # Compared as written. GitHub emits a lowercase id and
                # matches the fragment case-sensitively, so folding the
                # case here would only pass links a reader cannot
                # follow -- but it is worth its own message, because the
                # list of anchors below makes it look like a near miss.
                if anchor.lower() in anchors[path]:
                    dangling.append(
                        '%s links to %s, but GitHub ids are lowercase: '
                        '#%s differs from #%s only in case'
                        % (relpath, target, anchor, anchor.lower()))
                else:
                    dangling.append(
                        '%s links to %s, but %s has no heading whose '
                        'anchor is #%s (it has %d: %s)'
                        % (relpath, target, path, anchor,
                           len(anchors[path]),
                           ', '.join(sorted(anchors[path]))))
        return dangling, tally

    def test_a_dangling_link_is_reported(self):
        """The checker fails on a bad link, not only passes on good ones.

        The test below proves this tree is clean and the slug test
        proves the anchors are GitHub's; neither would notice a checker
        that reported nothing. An `_anchors` which returned a superset
        -- an over-broad fence toggle, a `_slug` that dropped the
        duplicate suffixing -- would leave both green, because the
        per-class floors catch "stopped matching", not "stopped
        failing".
        """
        root = self._tempdir()
        with open(os.path.join(root, 'target.md'), 'w',
                  encoding='utf-8') as f:
            f.write('# A Real Heading\n')
        with open(os.path.join(root, 'thing.py'), 'w',
                  encoding='utf-8') as f:
            f.write('# A comment which is not a heading\n')
        blob = 'https://github.com/shakenfist/kerbside/blob/develop'
        with open(os.path.join(root, 'source.md'), 'w',
                  encoding='utf-8') as f:
            f.write('[good](target.md#a-real-heading)\n'
                    '[bad](target.md#no-such-heading)\n'
                    '[wrong case](target.md#A-Real-Heading)\n'
                    '[gone](missing.md)\n'
                    '[source line](%s/thing.py#L1)\n'
                    '[absent source](%s/nope.py#L1)\n' % (blob, blob))

        dangling, tally = self._check_links(
            root, ['source.md', 'target.md'])

        self.assertEqual(4, len(dangling), '\n'.join(dangling))
        self.assertIn('#no-such-heading', dangling[0])
        self.assertIn('only in case', dangling[1])
        self.assertIn('missing.md', dangling[2])
        # A blob link into source still has its file checked, so a
        # renamed module is caught...
        self.assertIn('nope.py', dangling[3])
        # ...but its `#L1` is not looked for among thing.py's `#`
        # comments, which would fail with a list of comment-derived
        # slugs and no hint of why.
        self.assertNotIn('thing.py', '\n'.join(dangling))
        # The good link is checked and not complained about, so the
        # four complaints are not just "everything fails".
        self.assertNotIn('links to target.md#a-real-heading',
                         '\n'.join(dangling))
        self.assertEqual(4, tally['relative'])
        self.assertEqual(3, tally['anchors_relative'])
        self.assertEqual(2, tally['self_absolute_source'])
        self.assertEqual(0, tally['anchors_self_absolute_source'])

    def test_relative_markdown_links_resolve(self):
        root = _repo_root()
        if root is None:
            raise self.skipException(
                'no checkout above %s; markdown does not ship in the '
                'wheel' % os.path.abspath(__file__))

        files = self._markdown_files(root)
        dangling, tally = self._check_links(root, files)

        self.assertEqual([], dangling, '\n'.join(dangling))

        # Every link is accounted for, so a class of them cannot start
        # being skipped unnoticed.
        self.assertEqual(
            tally['matched'],
            sum(v for k, v in tally.items()
                if k != 'matched' and not k.startswith('anchors_')),
            'links were neither checked nor counted as skipped: %r'
            % dict(tally))

        # Floors on the classes this test exists for. A tree that
        # produced none of them would otherwise pass vacuously, which
        # is the failure these counts are here to catch.
        # Per class, not in total: an anchored class that stopped
        # being checked would otherwise hide behind the others.
        for kind in ('relative', 'self_absolute', 'in_page',
                     'anchors_relative', 'anchors_self_absolute',
                     'anchors_in_page'):
            self.assertNotEqual(
                0, tally[kind],
                'no %s links found in %d markdown files; the matcher or '
                'the classifier has stopped matching: %r'
                % (kind, len(files), dict(tally)))
