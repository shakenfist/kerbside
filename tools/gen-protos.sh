#!/bin/bash

# *Always* run this script via tox, like this:
#     tox -egenprotos
#
# It regenerates the Python protobuf + gRPC stubs for the Kerbside proxy RPC
# contract (kerbside/rpc/kerbside.proto) into kerbside/rpc/. The generated
# _pb2.py / _pb2_grpc.py / .pyi files are checked in; regenerate and commit
# them whenever kerbside.proto changes.

set -e

# Locate kerbside/rpc relative to this script (in tools/), so the script works
# regardless of the current working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPC_DIR="${SCRIPT_DIR}/../kerbside/rpc"

cd "${RPC_DIR}"

# Generate Python code, type stubs (.pyi), and gRPC stubs.
# --mypy_out generates proper type stubs via the mypy-protobuf plugin.
# --mypy_grpc_out generates typed stubs for the gRPC service definitions.
echo "Generating protobuf and gRPC stubs from kerbside.proto..."
python3 -m grpc_tools.protoc -I. \
    --python_out=. \
    --grpc_python_out=. \
    --mypy_out=. \
    --mypy_grpc_out=. \
    kerbside.proto

# gRPC lacks a python_package option, so the generated *_grpc.py / *_grpc.pyi
# files emit a flat "import kerbside_pb2". Rewrite that to a package-qualified
# import so the generated code is importable as part of the kerbside.rpc
# package.

# Detect OS for sed in-place syntax (macOS uses -i '', Linux uses -i).
if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_INPLACE="sed -i ''"
else
    SED_INPLACE="sed -i"
fi

for item in *.py *.pyi; do
    [ -e "${item}" ] || continue
    echo "Correcting kerbside_pb2 import in ${item}..."
    $SED_INPLACE 's/^import kerbside_pb2/from kerbside.rpc import kerbside_pb2/g' "${item}"
done

# The mypy-protobuf-generated _ServicerContext class causes issues with
# grpc-stubs due to conflicting definitions between grpc.ServicerContext and
# grpc.aio.ServicerContext. The generated "# type: ignore[misc, type-arg]"
# comment is kept as-is -- do not strip it.
