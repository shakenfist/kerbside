#!/usr/bin/python3

"""Assert the invariants a bound CI job depends on.

A bound job asks for a runner created for it alone: it names
bound-<image>, bound-<size> and a bind- token unique to its run, and
deliberately no plain vm, image or size label. See "Bound runners" in
docs/testing.md for why.

Every way that can go wrong fails the same silent way. GitHub gives a
job to any runner whose label set is a superset of the job's, so a job
whose labels are a subset of a bound runner's takes that runner and
runs happily on it while the bound job waits; and a bound job whose
labels no runner can satisfy -- a forgotten bind- token, a token the
provisioner's grammar rejects, two jobs sharing one token -- also just
waits. Neither reports red. GitHub holds a queued job for about 24
hours, and `Can enqueue: sf-e2e` is a required check, so a bound job
stuck in queue blocks every merge in the repository until someone
notices.

Nothing in a workflow file makes any of that visible, which is what
this script is for. It is the bound-runner sibling of
check-required-checks.sh, runs in sanity_checks, and converts those
failures from "discovered when merges stop working" into a red smoke
check.

The checks are pure functions of the tree so that the unit tests can
drive them over fixtures: see kerbside/tests/unit/test_bound_runners.py.
"""

import pathlib
import re
import sys

import yaml


BOUND_PREFIX = 'bound-'
BIND_PREFIX = 'bind-'

# The grammar the provisioner accepts, from shakenfist/private-ci's
# conductor/binding.py. A token it rejects is a malformed binding: the
# job gets no runner at all. The slug admits lowercase letters, digits
# and hyphens only, which is why the job id is not usable in a token --
# GitHub job ids conventionally carry underscores.
BIND_TOKEN_RE = re.compile(r'^bind-[0-9]+-[0-9]+-[a-z0-9-]+$')

EXPRESSION_RE = re.compile(r'\$\{\{(.+?)\}\}')

# The labels GitHub's runner adds of its own accord. config.sh is not
# passed --no-default-labels, so every runner in the fleet advertises
# these on top of what the provisioner asked for: confirmed against the
# live org runner list, where each one reads
# "self-hosted,Linux,X64,<configured labels>". They are part of what a
# bound runner advertises, so a job asking only for them -- the likeliest
# copy-paste out of GitHub's own documentation -- matches every bound
# runner in the fleet. No arm64 runner exists; adding one means adding
# its architecture label here.
IMPLICIT_LABELS = {'self-hosted', 'linux', 'x64'}

# Stand-ins for the two run-scoped values, which are digits at run time
# and need no more than that for any check here.
RUN_ID = '1'
RUN_ATTEMPT = '1'


class Unresolvable(Exception):
    """An expression this script cannot expand.

    Reported rather than ignored: an unexpanded label could render as
    anything, including something that steals a bound runner, so a new
    expression in a runs-on is a deliberate decision to extend this
    script rather than something to pass over quietly.
    """


def matrix_rows(job):
    """The matrix rows of a job, as a list of dicts, longest axis first.

    A job with no matrix has one, empty, row: the expansions below are
    then just the run-scoped ones.
    """
    matrix = (job.get('strategy') or {}).get('matrix') or {}
    for key in ('include', 'exclude'):
        if key in matrix:
            raise Unresolvable(
                'matrix %s changes which rows exist and by how much '
                'strategy.job-index moves, which this script does not '
                'model' % key)
    axes = {k: v for k, v in matrix.items() if isinstance(v, list)}
    if not axes:
        return [{}]
    if len(axes) > 1:
        raise Unresolvable(
            'a bound job may not have more than one matrix axis, because '
            'strategy.job-index then depends on the product order')
    name, values = next(iter(axes.items()))
    return [{name: value} for value in values]


def expand(label, job_id, row, index):
    """One label with its expressions resolved for one matrix row."""
    def resolve(match):
        expression = match.group(1).strip()
        if expression == 'github.run_id':
            return RUN_ID
        if expression == 'github.run_attempt':
            return RUN_ATTEMPT
        if expression == 'strategy.job-index':
            return str(index)
        if expression == 'github.job':
            return job_id
        if expression.startswith('matrix.'):
            value = row
            for part in expression.split('.')[1:]:
                if not isinstance(value, dict) or part not in value:
                    raise Unresolvable(
                        '%r names no value in this job\'s matrix' % expression)
                value = value[part]
            if not isinstance(value, str):
                raise Unresolvable('%r is not a string' % expression)
            return value
        raise Unresolvable('%r is not an expression this script expands'
                           % expression)

    return EXPRESSION_RE.sub(resolve, label)


def labels_of(job):
    """A job's runs-on as a list, whatever form it was written in."""
    runs_on = job.get('runs-on')
    if runs_on is None:
        return []
    if isinstance(runs_on, str):
        return [runs_on]
    if isinstance(runs_on, dict):
        return list(runs_on.get('labels') or [])
    return list(runs_on)


def read_jobs(workflow_dir):
    """Every job in every workflow, as (path, job_id, job) tuples."""
    jobs = []
    directory = pathlib.Path(workflow_dir)
    # GitHub honours both extensions, so a .yaml workflow must not be
    # able to hold a bound job this script never reads.
    paths = sorted(list(directory.glob('*.yml')) + list(directory.glob('*.yaml')))
    for path in paths:
        document = yaml.safe_load(path.read_text()) or {}
        for job_id, job in (document.get('jobs') or {}).items():
            if isinstance(job, dict):
                jobs.append((path.name, job_id, job))
    return jobs


def declared_labels(actionlint_path):
    """The self-hosted labels .github/actionlint.yaml declares."""
    document = yaml.safe_load(
        pathlib.Path(actionlint_path).read_text()) or {}
    runner = document.get('self-hosted-runner') or {}
    return _casefold(runner.get('labels') or [])


def check(workflow_dir, actionlint_path):
    """Every way the tree breaks a bound job, as a list of messages."""
    problems = []
    declared = declared_labels(actionlint_path)

    # Each job's labels as written, and -- where every expression in
    # them can be resolved -- as GitHub will render them, one set per
    # matrix row. A runner advertises the rendered form, so that is what
    # the superset rule has to be read against; the written form is what
    # tells us whether a bind- token is present at all.
    written = {}
    rendered = {}
    for path, job_id, job in read_jobs(workflow_dir):
        where = '%s:%s' % (path, job_id)
        written[where] = labels_of(job)
        try:
            rendered[where] = [
                {expand(label, job_id, row, index)
                 for label in written[where]}
                for index, row in enumerate(matrix_rows(job))]
        except Unresolvable as e:
            rendered[where] = None
            if _is_bound(written[where]):
                problems.append('%s: %s' % (where, e))

    bound = sorted(where for where in written if _is_bound(written[where]))

    for where in bound:
        tokens = [label for label in written[where]
                  if label.casefold().startswith(BIND_PREFIX)]
        if len(tokens) != 1:
            problems.append(
                '%s: a bound job needs exactly one bind- label, not %d. '
                'Without it the job matches every runner in its pool and '
                'is not bound at all.' % (where, len(tokens)))
        if 'self-hosted' not in _casefold(written[where]):
            problems.append(
                '%s: a bound job must still name self-hosted.' % where)
        for label in sorted(written[where]):
            if (label.casefold().startswith(BOUND_PREFIX)
                    and not EXPRESSION_RE.search(label)
                    and label.casefold() not in declared):
                problems.append(
                    '%s: label %r is not declared in %s, so actionlint '
                    'fails the workflow.'
                    % (where, label, pathlib.Path(actionlint_path).name))
        for row in rendered[where] or []:
            for label in sorted(row):
                # Matched as written, not casefolded: the provisioner's
                # grammar is case-sensitive even though GitHub's
                # scheduling is not, so Bind-1-1-lane is a malformed
                # binding rather than a working one.
                if (label.casefold().startswith(BIND_PREFIX)
                        and not BIND_TOKEN_RE.match(label)):
                    problems.append(
                        '%s: token %r is not bind-<run_id>-<attempt>-'
                        '<lowercase slug>, so the provisioner rejects it '
                        'and the job never gets a runner.' % (where, label))

    # Theft: another job whose labels are a subset of what a bound
    # runner advertises. A bound job never steals a peer's runner,
    # because its own token is not among the peer's labels -- unless two
    # tokens collide, which the next check covers.
    for where in bound:
        for row in rendered[where] or []:
            advertised = {label.casefold() for label in row} | IMPLICIT_LABELS
            for other in sorted(written):
                if other == where or not written[other]:
                    continue
                if rendered[other] is None:
                    if _casefold(_static(written[other])) <= advertised:
                        problems.append(
                            '%s names an expression this script cannot '
                            'expand, and the labels it does name are a '
                            'subset of bound job %s\'s, so it may be able '
                            'to take that runner. Teach expand() the '
                            'expression.' % (other, where))
                    continue
                for other_row in rendered[other]:
                    if _casefold(other_row) <= advertised:
                        problems.append(
                            '%s: labels %s are a subset of bound job '
                            '%s\'s, so GitHub can give it that job\'s '
                            'runner while the bound job waits.'
                            % (other, sorted(other_row), where))

    # Collision: two bound jobs in one workflow file that can render the
    # same token share one runner, and one of them queues forever.
    owners = {}
    for where in bound:
        path = where.split(':', 1)[0]
        for row in rendered[where] or []:
            for label in sorted(row):
                if not label.casefold().startswith(BIND_PREFIX):
                    continue
                owner = owners.setdefault((path, label), where)
                if owner != where:
                    problems.append(
                        '%s and %s can both render token %r in one run, so '
                        'they compete for one runner and one of them '
                        'queues forever.' % (owner, where, label))
    # A bound job with several matrix rows would otherwise report the
    # same thief once per row.
    return sorted(set(problems))


def _is_bound(labels):
    """Whether a job is asking to be bound, however badly.

    Case-insensitively, because GitHub matches labels that way: a job
    naming Bound-Debian-13 and Bind-... is bound as far as scheduling is
    concerned, and must not escape these checks over its spelling.
    """
    return any(label.casefold().startswith((BOUND_PREFIX, BIND_PREFIX))
               for label in labels)


def _static(labels):
    """The labels that carry no expression, so are known as written."""
    return {label for label in labels if not EXPRESSION_RE.search(label)}


def _casefold(labels):
    """Labels as GitHub compares them, which is without regard to case."""
    return {label.casefold() for label in labels}


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    problems = check(root / '.github' / 'workflows',
                     root / '.github' / 'actionlint.yaml')
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print('\nSee "Bound runners" in docs/testing.md.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
