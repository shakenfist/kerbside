#!/usr/bin/env python3

"""Extract the Proxmox VE account commands from docs/console-sources.md.

The Proxmox lane does not keep its own copy of the commands that create
kerbside's API token: it runs the documentation's. This reads the shell
block under "### Proxmox VE account", so a documented command that is wrong
fails the lane, and an edit to the documented commands is tested by it.

Two changes are made to what the documentation says:

- The user kerbside@pve is renamed kerbside-lane@pve, in the user and in
  every token ID. deploy-proxmox-on-shakenfist has already created a
  kerbside@pve user for its own token, so the documented "pveum user add"
  would otherwise fail on the lane's node.
- The token is created with "--output-format json", so that its secret can
  be taken from the command's output by a parser rather than by scraping a
  table meant for a person.

THIS TEXT RUNS AS ROOT. tools/proxmox-e2e/prepare-node.sh runs each command
with sudo on the lane's PVE node, so the block is refused unless every
command in it is one of the four the documentation needs: "pveum role add",
"pveum user add", "pveum acl modify" and "pveum user token add". Anything a
shell would read as a second command -- a ';', '&&', '|', a redirection, a
substitution -- is refused too, rather than quoted into a harmless
argument: a block like that does not say what a reader pasting it would
run. Each command is printed re-quoted with shlex.join, so the shell on the
node sees exactly the arguments checked here.

The token's user and name are refused too unless each is of the plain form
PVE IDs take: a user name@realm and a token name, each of letters, digits,
'.', '_' and '-' only. prepare-node.sh builds further root commands, and a
file path, from the token ID this prints, so a quote, a slash or a space in
either would reach the node's shell, or the runner's file system, unchecked.

Usage:
    tools/proxmox-e2e/account_commands.py [--doc PATH] [--token-id]

Prints one command per line, or with --token-id the ID of the token the
block creates. A refused block prints why to stderr and exits 1.
"""

import argparse
import re
import shlex
import sys
from pathlib import Path


HEADING = '### Proxmox VE account'
DOC_PATH = Path(__file__).resolve().parents[2] / 'docs' / 'console-sources.md'

# The user the documentation creates, and the user the lane creates instead.
DOC_USER = 'kerbside@pve'
LANE_USER = 'kerbside-lane@pve'

ALLOWED = (
    ('pveum', 'role', 'add'),
    ('pveum', 'user', 'add'),
    ('pveum', 'acl', 'modify'),
    ('pveum', 'user', 'token', 'add'),
)
TOKEN_ADD = ('pveum', 'user', 'token', 'add')

# The plain form of a PVE user ID and token name, the same shape
# drive-console.py's _TOKEN_ID requires of the whole token ID.
USER_ID = re.compile(r'^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$')
TOKEN_NAME = re.compile(r'^[A-Za-z0-9._-]+$')

# shlex's punctuation_chars: the characters a shell reads as a command
# separator, a pipe, a redirection or a subshell.
OPERATOR_CHARS = '();<>|&'
# Expansions, which run a command of their own inside an argument.
EXPANSION_CHARS = '$`'


class RefusedBlock(Exception):
    pass


def shell_block(markdown):
    """Return the lines of the one shell block in the account section."""
    lines = markdown.splitlines()
    try:
        start = lines.index(HEADING) + 1
    except ValueError:
        raise RefusedBlock('there is no "%s" section' % HEADING)

    blocks = []
    block = None
    for line in lines[start:]:
        if block is not None:
            if line.strip() == '```':
                blocks.append(block)
                block = None
            else:
                block.append(line)
        elif re.match(r'#{1,6} ', line):
            break
        elif line.strip() == '```shell':
            block = []
    if block is not None:
        raise RefusedBlock('the shell block under "%s" is not closed' % HEADING)
    if not blocks:
        raise RefusedBlock('there is no shell block under "%s"' % HEADING)
    if len(blocks) > 1:
        raise RefusedBlock('there is more than one shell block under "%s"' % HEADING)
    return blocks[0]


def _split(line):
    for c in EXPANSION_CHARS:
        if c in line:
            raise RefusedBlock('a command holds an expansion (%s): %s' % (c, line))
    lexer = shlex.shlex(line, posix=True, punctuation_chars=OPERATOR_CHARS)
    lexer.whitespace_split = True
    # shlex would start a comment at a '#' inside a word, and drop the rest
    # of the word with it. A shell starts one only at a word's first
    # character, so comments are found here instead.
    lexer.commenters = ''
    try:
        argv = list(lexer)
    except ValueError as e:
        raise RefusedBlock('a command cannot be parsed (%s): %s' % (e, line))
    for i, arg in enumerate(argv):
        if arg.startswith('#'):
            argv = argv[:i]
            break
    for arg in argv:
        if arg and all(c in OPERATOR_CHARS for c in arg):
            raise RefusedBlock('a command holds a shell operator (%s): %s' % (arg, line))
    return argv


def _rename(arg, old_user, new_user):
    # A user ID is renamed where it is a whole argument, the user part of a
    # token ID, or an item of a comma separated list of either.
    renamed = []
    for item in arg.split(','):
        if item == old_user:
            item = new_user
        elif item.startswith(old_user + '!'):
            item = new_user + item[len(old_user):]
        renamed.append(item)
    return ','.join(renamed)


def account_commands(markdown, old_user=DOC_USER, new_user=LANE_USER):
    """Return (commands, token_id) for the documentation's account block.

    commands is a list of argument lists, in the documentation's order.
    token_id is the ID of the one token the block creates. Raises
    RefusedBlock if the block is missing, empty, holds a command outside
    the allowlist, or does not create exactly one token, with a plain user
    and token name.
    """
    # A trailing backslash continues a command onto the next line, as it
    # would in a shell.
    text = '\n'.join(shell_block(markdown)).replace('\\\n', ' ')

    commands = []
    for line in text.split('\n'):
        argv = _split(line)
        if not argv:
            continue
        if not any(tuple(argv[:len(allowed)]) == allowed for allowed in ALLOWED):
            raise RefusedBlock('a command is not one the account needs: %s' % line)
        commands.append([_rename(arg, old_user, new_user) for arg in argv])
    if not commands:
        raise RefusedBlock('the shell block under "%s" is empty' % HEADING)

    token_adds = [argv for argv in commands if tuple(argv[:len(TOKEN_ADD)]) == TOKEN_ADD]
    if len(token_adds) != 1:
        raise RefusedBlock('the block creates %d tokens, not one' % len(token_adds))
    token_add = token_adds[0]
    if len(token_add) < len(TOKEN_ADD) + 2:
        raise RefusedBlock('the token is created without a user and a token name: %s' % shlex.join(token_add))
    user, token_name = token_add[len(TOKEN_ADD)], token_add[len(TOKEN_ADD) + 1]
    if not USER_ID.match(user):
        raise RefusedBlock('the token\'s user is not of the form name@realm: %s' % shlex.join(token_add))
    if not TOKEN_NAME.match(token_name):
        raise RefusedBlock('the token\'s name is not a plain PVE token name: %s' % shlex.join(token_add))
    token_id = '%s!%s' % (user, token_name)
    if '--output-format' not in token_add:
        token_add.extend(['--output-format', 'json'])
    return commands, token_id


def main():
    parser = argparse.ArgumentParser(description='Extract the Proxmox VE account commands from the documentation.')
    parser.add_argument('--doc', default=str(DOC_PATH), help='The documentation to read (default %(default)s)')
    parser.add_argument('--token-id', action='store_true', help='Print the ID of the token, not the commands')
    args = parser.parse_args()

    with open(args.doc) as f:
        markdown = f.read()
    try:
        commands, token_id = account_commands(markdown)
    except RefusedBlock as e:
        print('account_commands.py: refusing %s: %s' % (args.doc, e), file=sys.stderr)
        return 1

    if args.token_id:
        print(token_id)
    else:
        for argv in commands:
            print(shlex.join(argv))
    return 0


if __name__ == '__main__':
    sys.exit(main())
