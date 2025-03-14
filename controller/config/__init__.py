from pathlib import Path

ROOT_PATH = Path(__file__).parent.parent.parent.resolve()
INFRA_CONFIG_PATH = str(ROOT_PATH / "config_files" / "infra_config.yaml")
TEST_INFRA_CONFIG_PATH = str(ROOT_PATH / "config_files" / "infra_config_test.yaml")
TEST_DOMAIN_CONFIG_PATH = str(ROOT_PATH / "config_files" / "domain_config_test.yaml")
DOMAIN_CONFIG_PATH = str(ROOT_PATH / "config_files" / "domain_config.yaml")
