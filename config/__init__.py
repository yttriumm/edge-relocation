from pathlib import Path


INFRA_CONFIG_PATH = str(Path(__file__).parent.resolve() / "infra_config.yaml")
INFRA_TEST_CONFIG_PATH = INFRA_CONFIG_PATH = str(Path(__file__).parent.resolve() / "infra_config_test.yaml")
DOMAIN_CONFIG_PATH = str(Path(__file__).parent.resolve() / "domain_config.yaml")