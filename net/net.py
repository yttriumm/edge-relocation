import subprocess
import threading
from apiflask import APIFlask, fields
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink, TCIntf
from mininet.node import RemoteController
from mininet.log import setLogLevel

from config import INFRA_CONFIG_PATH
from config.infra_config import InfraConfig

app = APIFlask(__name__)


def run_cmd():
    subprocess.Popen("sudo mn -c", shell=True, stdout=subprocess.PIPE).communicate()


def mn():
    config: InfraConfig = InfraConfig.from_file(INFRA_CONFIG_PATH)
    switches = {}
    links = []

    net = Mininet(waitConnected=True, controller=RemoteController, autoStaticArp=False)
    for switch in config.switches:
        switches[switch.name] = net.addSwitch(name=switch.name, dpid=switch.dpid)
    for host in config.hosts:
        h = net.addHost(name=host.name, mac=host.mac, ip=None)
        net.addLink(host.name, host.switch, port1=0, port2=host.switch_port)

    for link in config.links:
        l = net.addLink(node1=link.src,
                        node2=link.dst,
                        port1=link.src_port,
                        port2=link.dst_port, cls=TCLink)
        links.append(l)
    controller = net.addController(name=config.controller.name, ip=config.controller.ip, port=config.controller.port)

    def add_table_miss_entries():
        for switch in net.switches:
            switch.cmd(f'sudo ovs-ofctl add-flow {switch.name} priority=0,actions=controller')

    def disable_ipv6():
        for host in net.hosts:
            host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
            host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
            host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        for sw in net.switches:
            sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
            sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
            sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    def register_hosts():
        for host in config.hosts:
            net.getNodeByName(host.name).cmd(f"dhclient -cf net/dhcp/dhcp_{host.network}.conf {host.name}-eth0 &")
            # net.getNodeByName(host.name).cmd(f"ip r add default dev {host.name}-eth0")
    # @app.route("/relocate")
    # def relocate():
    #     old_link = net.linksBetween(server, switches[config.server.link_before.dst])[0]
    #     old_mac = server.MAC()
    #     net.delLink(old_link)
    #     net.addLink(node1=config.server.name, node2=config.server.link_after.dst, port1=config.server.link_after.src_port, port2=config.server.link_after.dst_port)
    #     server_intf: Intf = server.intfs[0]
    #     server_intf.setMAC(old_mac)
    #     server_intf.setIP(ipstr=config.server.service_ip, prefixLen=24)
    #     server.cmd(f"ip r a {config.host.ip} dev {config.server.name}-eth{config.server.link_after.src_port}")
    #     server.cmd(f"sudo arp -s {config.host.ip} {host.MAC()}")
    #     new_switch = config.server.link_after.dst
    #     new_switch_port = config.server.link_after.dst_port
    #     subprocess.Popen(f"sudo ovs-vsctl add-port {new_switch} {new_switch}-eth{new_switch_port} -- set Interface {new_switch}-eth{new_switch_port} ofport={new_switch_port}", shell=True, stdout=subprocess.PIPE).communicate()
    #     return f"Changed server's attachment point from {config.server.link_before.dst} to {config.server.link_after.dst}", 200

    @app.patch("/links/<string:switch1>/<string:switch2>")
    @app.input({"delay": fields.Integer(required=True)})
    def change_link_params(switch1: str, switch2: str, json_data):
        try:
            node1 = net.getNodeByName(switch1)
            node2 = net.getNodeByName(switch2)
            link: TCLink = net.linksBetween(node1, node2)[0]
            delay = str(json_data["delay"])
            intf1: TCIntf = link.intf1  # type: ignore
            intf2: TCIntf = link.intf2  # type: ignore
            intf1.config(delay=f"{delay}ms")
            intf2.config(delay=f"{delay}ms")
            return "OK", 200
        except Exception as e:
            return str(e), 500

    disable_ipv6()
    net.build()
    net.start()
    add_table_miss_entries()
    register_hosts()
    t = threading.Thread(target=app.run, kwargs=dict(port=2001))
    t.start()
    CLI(net)
    net.stop()
    subprocess.Popen("sudo mn -c", shell=True, stdout=subprocess.PIPE).communicate()


if __name__ == "__main__":
    setLogLevel("info")
    mn()
