from controller.switch import SDNSwitch


def test_switch(fake_switch: SDNSwitch):
    assert 1


def test_scenario(switch_in_scenario: SDNSwitch):
    assert 1
