#!/usr/bin/env python3

"""Fetch the oVirt lane's base image into the under-cloud before it is needed.

The oVirt lane boots its engine guest from rocky:8, a 1.9 GB image, in the
runner's own throwaway namespace, so the under-cloud fetches it afresh from
images.shakenfist.com on every run. That fetch used to start only when the
instance did, as a dependency of the instance's start operation, and
Shaken Fist gives a start about six minutes of dependency waiting
(DEPENDENCY_DEFER_BUDGET) before it abandons the start. Green runs took
four minutes to fetch the image; slow ones took ten, and three merge queue
runs in October 2026 failed in "Build infrastructure" that way, reported as
"not created within 598 second timeout (last state: initial)" -- which
read as a capacity problem and was filed as one (#284).

This asks the under-cloud to cache the image as an artifact in the same
namespace, which is the artifact the instance's disk then resolves to, and
waits for it. A cache request is a fetch operation of its own with nothing
to wait for, so no defer budget applies to it, and the instance's start
then finds the image already in the cluster.

It never fails the job. Pre-caching is an optimisation: when it cannot be
done, "Build infrastructure" still fetches the image itself, as it did
before, and fails or passes on its own merits. Problems are reported as
GitHub Actions warnings.

Usage:
    tools/ovirt-e2e/precache-image.py IMAGE NAMESPACE [--timeout SECONDS]

Runs with the runner's system python3, which has shakenfist_client and the
runner's under-cloud credentials, as sf-client does.
"""

import argparse
import sys
import time


def warn(message):
    print(f'::warning::Pre-caching the base image: {message}')


def main():
    parser = argparse.ArgumentParser(description='Cache a base image in an under-cloud namespace.')
    parser.add_argument('image', help='The image URL or shorthand, e.g. rocky:8')
    parser.add_argument('namespace', help='The namespace the lane creates its instances in')
    parser.add_argument('--timeout', type=int, default=1500,
                        help='Seconds to wait for the fetch to finish (default 1500)')
    parser.add_argument('--poll', type=int, default=10, help='Seconds between checks (default 10)')
    args = parser.parse_args()

    try:
        from shakenfist_client import apiclient
        client = apiclient.Client()
        artifact = client.cache_artifact(args.image, namespace=args.namespace)
    except Exception as e:
        warn(f'the cache request failed ({e}); Build infrastructure will fetch it instead')
        return 0

    uuid = artifact.get('uuid')
    print(f'Caching {args.image} in namespace {args.namespace} as artifact {uuid}')
    start = time.time()
    state = artifact.get('state')
    while True:
        if state == 'created':
            print(f'{args.image} is cached, after {time.time() - start:.0f} seconds')
            return 0
        if state in ('error', 'deleted'):
            warn(f'artifact {uuid} went to state {state}; Build infrastructure will fetch it instead')
            return 0
        if time.time() - start > args.timeout:
            warn(f'artifact {uuid} was still {state} after {args.timeout} seconds; '
                 'Build infrastructure will wait for it')
            return 0

        time.sleep(args.poll)
        try:
            state = client.get_artifact(uuid).get('state')
        except Exception as e:
            warn(f'could not read artifact {uuid} ({e}); Build infrastructure will fetch it instead')
            return 0
        print(f'  {time.time() - start:.0f}s: {state}')


if __name__ == '__main__':
    sys.exit(main())
