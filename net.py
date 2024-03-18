import subprocess
import yaml
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel

from scenario import Config

def mn():
    config: Config = Config.from_file("scenario.yaml")
    switches = {}
    host = None
    server = None
    controller = None

    net = Mininet(waitConnected=False, controller=RemoteController)
    for switch in config.switches:
        switches[switch.name] = net.addSwitch(name=switch.name, dpid=switch.dpid)
    for link in config.links:
        net.addLink(node1=link.src,
                    node2=link.dst,
                    port1=link.src_port,
                    port2=link.dst_port)
    controller = net.addController(name=config.controller.name, ip=config.controller.ip, port=config.controller.port)
    host = net.addHost(
        name=config.host.name, ip=config.host.ip)
    server = net.addHost(
        name=config.server.name, ip=config.server.service_ip)
    net.addLink(node1=config.host.name, node2=config.host.attachment_point)
    net.addLink(node1=config.server.name, node2=config.server.source_switch)

    for host in net.hosts:    
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


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
