import hashlib
import os

import testtools

from kerbside.rpc import contract
from kerbside.rpc import kerbside_pb2


class ContractHashTestCase(testtools.TestCase):
    """Pin CONTRACT_HASH to the actual bytes of kerbside.proto.

    This is the safety net for decision 3: if the proto changes without
    re-running `tox -egenprotos`, this test fails tox -epy3 rather than
    letting a stale CONTRACT_HASH silently ship.
    """

    def test_hash_matches_proto_bytes(self):
        # kerbside_pb2's __file__ lives alongside kerbside.proto in the
        # kerbside.rpc package, so locate the proto relative to it rather
        # than relative to this test file.
        rpc_dir = os.path.dirname(kerbside_pb2.__file__)
        proto_path = os.path.join(rpc_dir, 'kerbside.proto')

        with open(proto_path, 'rb') as f:
            proto_bytes = f.read()

        expected = hashlib.sha256(proto_bytes).hexdigest()
        self.assertEqual(expected, contract.CONTRACT_HASH)

    def test_hash_is_64_lowercase_hex_chars(self):
        self.assertRegex(contract.CONTRACT_HASH, r'^[0-9a-f]{64}$')
