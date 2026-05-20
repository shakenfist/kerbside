import os

from tempest import config
from tempest.test_discover import plugins

from kerbside_tempest_plugin import config as project_config


class KerbsideTempestPlugin(plugins.TempestPlugin):

    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = 'kerbside_tempest_plugin/tests'
        return os.path.join(base_path, test_dir), base_path

    def register_opts(self, conf):
        config.register_opt_group(
            conf,
            project_config.kerbside_group,
            project_config.KerbsideGroup,
        )

    def get_opt_lists(self):
        return [(
            project_config.kerbside_group.name,
            project_config.KerbsideGroup,
        )]

    def get_service_clients(self):
        return []
