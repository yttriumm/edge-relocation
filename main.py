import subprocess
import yaml
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel

def mn():
    with open("scenario.yaml", "r") as f:
        scenario = yaml.full_load(f.read())
    switches = {}
    host = None
    server = None
    controller = None
    controller_data = scenario["controller"]

    net = Mininet(waitConnected=True, controller=RemoteController)
    for switch in scenario["switches"]:
        name = switch["name"]
        switches[name] = net.addSwitch(name=name, dpid=switch["dpid"])
    for link in scenario["links"]:
        source_name = link["src"]
        destination_name = link["dst"]
        source_port = link["src_port"]
        destination_port=link["dst_port"]
        net.addLink(node1=switches[source_name],
                    node2=switches[destination_name],
                    port1=source_port,
                    port2=destination_port)
    controller = net.addController(name=controller_data["name"], ip=controller_data["ip"], port=controller_data["port"])
    scenario_data = scenario["scenario"]
    host = net.addHost(
        name=scenario_data["host"]["name"], ip=scenario_data["host"]["ip"])
    server = net.addHost(
        name=scenario_data["server"]["name"], ip=scenario_data["server"]["service_ip"])
    net.addLink(node1=switches[scenario_data["server"]
                ["source_switch"]], node2=server)
    net.addLink(node1=switches[scenario_data["host"]
                               ["attachment_point"]], node2=host)
    
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    for sw in net.switches:
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
    net.build()
    net.start()
    CLI(net)
    net.stop()
    subprocess.Popen("sudo mn -c", shell=True, stdout=subprocess.PIPE).communicate()


if __name__ == "__main__":
    setLogLevel("info")
    mn()
