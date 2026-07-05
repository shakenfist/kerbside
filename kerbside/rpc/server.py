from concurrent import futures
import os

import grpc

from shakenfist_utilities import logs

from kerbside.config import config
from kerbside import util
from kerbside.rpc import kerbside_pb2_grpc
from kerbside.rpc.servicer import KerbsideProxyServicer


LOG, _ = logs.setup(__name__, **util.configure_logging())


def serve(socket_path=None, workers=None):
    """Build and start the KerbsideProxy gRPC server on a unix socket.

    The servicer is registered before the server is started, per the
    grpc lifecycle. The gRPC server runs on its own ThreadPoolExecutor
    threads, so this returns immediately with the started server object;
    the caller owns its lifetime and is responsible for stopping it (see
    stop()). We intentionally do NOT call wait_for_termination() here so
    the daemon's maintenance loop is unaffected and tests can drive the
    server directly.
    """
    if socket_path is None:
        socket_path = config.API_SOCKET_PATH
    if workers is None:
        workers = config.API_GRPC_WORKERS

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers))
    kerbside_pb2_grpc.add_KerbsideProxyServicer_to_server(
        KerbsideProxyServicer(), server)

    # Prepare the socket: the containing directory is created with
    # restrictive permissions and any stale socket file is removed before
    # we bind (mirroring shakenfist's trusted-local-peer model).
    socket_dir = os.path.dirname(socket_path)
    if socket_dir:
        os.makedirs(socket_dir, mode=0o700, exist_ok=True)
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    server.add_insecure_port('unix:%s' % socket_path)
    server.start()
    LOG.info('KerbsideProxy gRPC server listening on unix:%s' % socket_path)
    return server


def stop(server, socket_path=None, grace=1.0):
    """Stop the gRPC server and clean up its socket.

    Blocks until the graceful shutdown completes (up to grace seconds),
    then unlinks the socket file. Pass the same socket_path given to
    serve() so a non-default socket (e.g. a test's temporary path) is
    cleaned up; it defaults to config.API_SOCKET_PATH.
    """
    if socket_path is None:
        socket_path = config.API_SOCKET_PATH
    server.stop(grace).wait()
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    LOG.info('KerbsideProxy gRPC server stopped')
