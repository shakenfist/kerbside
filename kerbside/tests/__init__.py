import os


# kerbside.api refuses to import while AUTH_SECRET_SEED is unset (issue
# #131), and several test modules import it. Setting it here, before any
# test module imports kerbside.config, works whichever runner collects the
# tests. setdefault leaves a seed from the environment alone.
os.environ.setdefault(
    'KERBSIDE_AUTH_SECRET_SEED', 'not-a-secret-unit-test-seed')
