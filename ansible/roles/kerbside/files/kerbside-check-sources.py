#!/usr/bin/env python3
# Copyright 2026 Michael Still and contributors

"""Check a rendered sources.yaml before it replaces the running one.

Usage: kerbside-check-sources.py SOURCES.yaml
       kerbside-check-sources.py - < SOURCES.yaml
       kerbside-check-sources.py --json - < SOURCES.json

Kerbside's daemon reads sources.yaml on every scrape pass, and a file it cannot
use crash-loops it (kerbside#465), or errors a source. The role therefore runs
this as the write task's validate command, so a bad file is refused and the old
one stays in place. The validate entry point runs it too, on the control node
with the file on stdin, so that a bad kerbside_sources is refused before any
host is changed. It passes kerbside_sources as JSON (--json) rather than
rendered YAML: by then Ansible has already parsed the operator's variables,
so an unquoted password such as 012345 is the number 5349, which rendering
would write back as 5349 and a YAML check would accept as text. JSON keeps
the type, and the number is refused.

The file is loaded as Kerbside loads it, with a YAML loader which leaves every
unquoted number as the text it spells, and must be a non-empty list of
mappings. Each is checked by the rules of Kerbside's source loader and of the
driver for its type (docs/console-sources.md):

* every source has a source and a type, and no two share a source name;
* the type is shakenfist, ovirt, openstack, proxmox or static;
* the fields every source shares (url, username, password and the like) are
  text when they are present, since Kerbside refuses the whole file otherwise;
* each type's required fields are present and non-empty text. A Shaken Fist
  source's username is system, since Kerbside scrapes the whole cluster with
  that credential and accepts no other. A Proxmox VE source's url is https,
  since its driver refuses anything else;
* a static source has a consoles list, each of whose entries carries the
  fields the static driver requires, as text or port numbers.

The file holds every source's password and every static console's ticket, so
no message here ever includes a value, or the text around a YAML error.
Messages name sources and consoles by their position, and fields by their key.

Exits 0 when the file is good, and 1 with the reasons on stderr when it is not.
"""

import json
import sys
import urllib.parse

import yaml


# The fields every source must have, and the optional fields Kerbside's loader
# requires to be text whenever they are present.
COMMON_REQUIRED = ('source', 'type')
COMMON_TEXT = ('url', 'username', 'password', 'project_name',
               'user_domain_id', 'project_domain_id', 'ca_cert')

# Each source type Kerbside knows, and the fields its driver cannot do without.
# A static source's one required field, consoles, is checked on its own.
TYPE_REQUIRED = {
    'shakenfist': ('url', 'username', 'password', 'ca_cert'),
    'ovirt': ('url', 'username', 'password', 'ca_cert'),
    'openstack': ('url', 'username', 'password', 'project_name',
                  'user_domain_id', 'project_domain_id'),
    'proxmox': ('url', 'username', 'password', 'ca_cert'),
    'static': (),
}

# The username a Shaken Fist source must authenticate as.
SHAKENFIST_USERNAME = 'system'

# A static console's required fields, those which are port numbers, and the
# optional one which is text.
CONSOLE_REQUIRED = ('uuid', 'name', 'hypervisor', 'hypervisor_ip',
                    'insecure_port', 'ticket')
CONSOLE_PORTS = ('insecure_port', 'secure_port')
CONSOLE_OPTIONAL_TEXT = ('host_subject',)

# Kerbside reads sources.yaml without YAML's number and date resolvers, so a
# password written as 012345 is that text, not the octal 5349. This does the
# same, so that a value is judged as Kerbside will see it.
_SPELLED_TAGS = ('tag:yaml.org,2002:int', 'tag:yaml.org,2002:float',
                 'tag:yaml.org,2002:timestamp')


class _SourcesLoader(yaml.SafeLoader):
    """A SafeLoader which leaves numbers and dates as the text written."""


# A filtered copy: SafeLoader's own table is shared by every
# yaml.safe_load() in the process, and must not change.
_SourcesLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers
            if tag not in _SPELLED_TAGS]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _is_text(value):
    return isinstance(value, str)


def _is_filled(value):
    return _is_text(value) and bool(value.strip())


def _is_port(value):
    if isinstance(value, str):
        if not (value.isascii() and value.isdecimal()):
            return False
        value = int(value)
    elif isinstance(value, bool) or not isinstance(value, int):
        return False
    return 1 <= value <= 65535


def _load(stream):
    """Return the loaded file and None, or None and the reason it failed."""
    try:
        return yaml.load(stream, Loader=_SourcesLoader), None
    except yaml.MarkedYAMLError as e:
        mark = e.problem_mark or e.context_mark
        where = ' at line %d' % (mark.line + 1) if mark else ''
        return None, 'the file is not valid YAML%s' % where
    except (yaml.YAMLError, UnicodeDecodeError):
        return None, 'the file is not valid YAML'
    except Exception as e:
        return None, 'the file could not be read: %s' % type(e).__name__


def _check_console(where, console):
    """Return the reasons one static console entry is unusable."""
    if not isinstance(console, dict):
        return ['%s is not a mapping' % where]

    errors = ['%s: %s is missing' % (where, key)
              for key in CONSOLE_REQUIRED if key not in console]
    for key in CONSOLE_REQUIRED + CONSOLE_OPTIONAL_TEXT:
        if key in CONSOLE_PORTS or key not in console:
            continue
        if key in CONSOLE_OPTIONAL_TEXT and console[key] is None:
            continue
        if not _is_text(console[key]):
            errors.append('%s: %s is not text' % (where, key))
    for key in CONSOLE_PORTS:
        if key not in console:
            continue
        if key not in CONSOLE_REQUIRED and console[key] is None:
            continue
        if not _is_port(console[key]):
            errors.append('%s: %s is not a port from 1 to 65535'
                          % (where, key))
    return errors


def _check_source(index, source):
    """Return the reasons one entry of the list is not a usable source."""
    if not isinstance(source, dict):
        return ['source %d is not a mapping' % index]

    errors = []
    for key in COMMON_REQUIRED:
        if not _is_filled(source.get(key)):
            errors.append('source %d: %s is missing, or is not non-empty text'
                          % (index, key))
    for key in COMMON_TEXT:
        if source.get(key) is not None and not _is_text(source[key]):
            errors.append('source %d: %s is not text' % (index, key))

    kind = source.get('type')
    if not _is_filled(kind):
        return errors
    if kind not in TYPE_REQUIRED:
        errors.append('source %d: type is not one of %s'
                      % (index, ', '.join(sorted(TYPE_REQUIRED))))
        return errors

    # A value which is there but not text was refused above.
    for key in TYPE_REQUIRED[kind]:
        value = source.get(key)
        if value is None:
            errors.append('source %d (%s): %s is missing'
                          % (index, kind, key))
        elif _is_text(value) and not value.strip():
            errors.append('source %d (%s): %s is empty' % (index, kind, key))

    if kind == 'shakenfist':
        username = source.get('username')
        if _is_filled(username) and username != SHAKENFIST_USERNAME:
            errors.append(
                'source %d (shakenfist): username is not %s, but Kerbside '
                'scrapes a Shaken Fist cluster only with its %s credential'
                % (index, SHAKENFIST_USERNAME, SHAKENFIST_USERNAME))

    if kind == 'proxmox':
        url = source.get('url')
        if _is_filled(url) and urllib.parse.urlsplit(url).scheme != 'https':
            errors.append('source %d (proxmox): url is not https, which '
                          'Kerbside refuses for Proxmox VE' % index)

    if kind == 'static':
        consoles = source.get('consoles')
        if 'consoles' not in source:
            errors.append('source %d (static): consoles is missing; write '
                          'consoles: [] for a source with none' % index)
        elif not isinstance(consoles, list):
            errors.append('source %d (static): consoles is not a list'
                          % index)
        else:
            for position, console in enumerate(consoles):
                errors.extend(_check_console(
                    'source %d console %d' % (index, position), console))
    return errors


def _load_json(stream):
    """Return the loaded JSON and None, or None and the reason it failed."""
    try:
        return json.load(stream), None
    except ValueError as e:
        return None, 'the input is not valid JSON at line %d' % e.lineno


def check_stream(stream, as_json=False):
    """Return a list of reasons stream is not a good sources.yaml.

    With as_json, stream is kerbside_sources as JSON, whose values keep the
    types Ansible gave them, so a credential written as a number is refused
    rather than read as the text of that number.
    """
    sources, error = (_load_json if as_json else _load)(stream)
    if error:
        return [error]

    if not isinstance(sources, list) or not sources:
        return ['the file is not a non-empty list of sources']

    errors = []
    first_with_name = {}
    for index, source in enumerate(sources):
        errors.extend(_check_source(index, source))
        if not isinstance(source, dict) or not _is_text(source.get('source')):
            continue
        name = source['source']
        if name in first_with_name:
            errors.append('sources %d and %d share a source name, which '
                          'must be unique' % (first_with_name[name], index))
        else:
            first_with_name[name] = index
    return errors


def check(path, as_json=False):
    """Return a list of reasons path is not a good sources.yaml."""
    if path == '-':
        return check_stream(sys.stdin, as_json)
    try:
        with open(path) as f:
            return check_stream(f, as_json)
    except OSError as e:
        return ['the file could not be read: %s' % e.strerror]


def main(argv):
    as_json = len(argv) == 3 and argv[1] == '--json'
    if len(argv) != (3 if as_json else 2):
        sys.stderr.write('usage: %s [--json] SOURCES\n' % argv[0])
        return 2

    errors = check(argv[-1], as_json)
    for error in errors:
        sys.stderr.write('sources.yaml refused: %s\n' % error)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
