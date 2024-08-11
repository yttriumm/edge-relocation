from pathlib import Path

ROOT_PATH = Path(__file__).parent.parent.resolve()
INFRA_CONFIG_PATH = str(ROOT_PATH / "config_files" / "infra_config.yaml")
INFRA_TEST_CONFIG_PATH = INFRA_CONFIG_PATH = str(ROOT_PATH / "config_files" / "infra_config_test.yaml")
DOMAIN_CONFIG_PATH = str(ROOT_PATH/ "config_files" /"domain_config.yaml")