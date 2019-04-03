#!/usr/bin/env ruby

require 'sshkit'
require 'sshkit/dsl'
require 'resolv'
require 'fileutils'
require 'yaml'
require 'os'
require 'json'

include FileUtils
include SSHKit::DSL

SSHKit::Backend::Netssh.configure do |ssh|
  ssh.ssh_options = {
    known_hosts: SSHKit::Backend::Netssh::KnownHosts.new,
    auth_methods: ['publickey'],
    forward_agent: false,
    timeout: 10,
    keys: ['~/.ssh/id_rsa'],
  }
end

CONFIG_YML = 'config.yml'

class Server
  def initialize(session, config={})
    @session = session
    @config = config
    @domain = config['domain']
    @wireguard = config['wireguard']
    @v2ray = config['v2ray']
    ip = Resolv.getaddress(@domain)
    @pub_ip = ip
  end

  def check_os
    if @session.test('[ -e /etc/lsb-release ]')
      lsb = @session.capture('cat /etc/lsb-release').lines.map{|l| l.strip.split('=')}.to_h
      release = lsb['DISTRIB_RELEASE']
      major, minor = release.split('.').map(&:to_i)
      return if major >= 18
    end
    raise 'This script is only compatible with Ubuntu 18.04 and up.'
  end

  def client_configs_dir
    path = '/root/client_configs'
    @session.execute("mkdir -p #{path}")
    path
  end

  def install_wireguard
    return if @wireguard.nil?
    return if @session.test("[ -f /usr/bin/wg ]")
    @session.execute("add-apt-repository -y ppa:wireguard/wireguard")
    @session.execute("apt-get update")
    @session.execute("apt-get install -y wireguard")
    wg_config_dir = '/etc/wireguard'
    @session.execute("umask 077 #{wg_config_dir}")
    # Server public and private key
    wg_server_private = @session.capture("/usr/bin/wg genkey")
    @session.upload!(StringIO.new(wg_server_private), "#{wg_config_dir}/server_private")
    wg_server_public = @session.capture("echo #{wg_server_private} | /usr/bin/wg pubkey")
    @session.upload!(StringIO.new(wg_server_public), "#{wg_config_dir}/server_public")

    # Client public and private key
    @wireguard['clients'].each do |client|
      wg_client_private = @session.capture("/usr/bin/wg genkey")
      @session.upload!(StringIO.new(wg_client_private), "#{client_configs_dir}/client_private_#{client}")
      wg_client_public = @session.capture("echo #{wg_client_private} | /usr/bin/wg pubkey")
      @session.upload!(StringIO.new(wg_client_public), "#{client_configs_dir}/client_public_#{client}")
    end

    iface = default_iface
    port = @wireguard['port'] || 54321
    server_conf = <<END
[Interface]
# Server private key
PrivateKey = #{wg_server_private}
Address = #{@wireguard['wg_ip']}
ListenPort = #{port}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o #{iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o #{iface} -j MASQUERADE
END

    @wireguard['clients'].each do |client|
      wg_client_public = @session.capture("cat #{client_configs_dir}/client_public_#{client}")
      peer = <<END
[Peer]
# Client public key
PublicKey = #{wg_client_public}
AllowedIPs = #{client}/32
END
      server_conf += peer
    end
    @session.upload!(StringIO.new(server_conf), "#{wg_config_dir}/wg0.conf")
    @session.execute("/bin/systemctl enable wg-quick@wg0")
    @session.execute("/bin/systemctl start wg-quick@wg0")

    @wireguard['clients'].each do |client|
      wg_client_private = @session.capture("cat #{client_configs_dir}/client_private_#{client}")
      client_conf = <<END
[Interface]
# Client private key
PrivateKey = #{wg_client_private}
Address = #{client}/32
DNS = 8.8.8.8
MTU = 1420

[Peer]
# Server public key
PublicKey = #{wg_server_public}
AllowedIPs = 0.0.0.0/0
Endpoint = #{@domain}:#{port}
PersistentKeepalive = 25
END
      client_conf_path = "#{client_configs_dir}/client_#{client}.conf"
      @session.upload!(StringIO.new(client_conf), client_conf_path)
    end
  end

  def show_client_config_qr
    if @wireguard
      @session.execute("apt-get install -y qrencode")
      @wireguard['clients'].each do |client|
        @session.info("Wireguard client config for #{client}:")
        client_conf_path = "#{client_configs_dir}/client_#{client}.conf"
        qr = @session.capture("qrencode -t ansiutf8 < #{client_conf_path}")
        puts qr
        @session.info("\n")
      end
    end
    if @v2ray
      v2ray_conf = JSON.parse(@session.capture("cat /etc/v2ray/config.json"))
      port = @v2ray['port'] || 50443
      uuids = v2ray_conf['inbound']['settings']['clients'].map { |client| client['id'] }
      uuids.each do |uuid|
        @session.info("V2Ray client config for #{uuid}:")
        @session.info("    server: #{@domain}")
        @session.info("    port: #{port}")
        @session.info("    security: aes-128-gcm")
        @session.info("    level: 1")
        @session.info("    alterId: 100")
        if @v2ray['show_qr']
          client_conf_path = File.join(client_configs_dir, "v2ray_#{uuid}.conf")
          qr = @session.capture("qrencode -t ansiutf8 < #{client_conf_path}")
          puts qr
        end
        @session.info("\n")
      end
    end
  end

  def install_v2ray
    return if @v2ray.nil?
    return if @session.test("[ -f /usr/bin/v2ray/v2ray ]")
    @session.execute("apt-get install -y uuid")
    @session.execute("bash <(curl -L -s https://install.direct/go.sh)")
    number_of_clients = @v2ray['clients'].to_i
    uuids = (0...number_of_clients).map { @session.capture('/usr/bin/uuid') }
    clients = uuids.map { |uuid|  {'id' => uuid, "security" => "aes-128-gcm", "level" => 1, "alterId" => 100}.to_json }.join(",\n")
    port = @v2ray['port'] || 50443
    server_conf = <<END
{
    "log": {
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log",
        "loglevel": "warning"
    },
    "inbound": {
        "port": #{port},
        "protocol": "vmess",
        "settings": {
            "clients": [
                #{clients}
            ]
        }
    },
    "outbound": {
        "protocol": "freedom",
        "settings": {}
    },
    "inboundDetour": [],
    "outboundDetour": [
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "strategy": "rules",
        "settings": {
            "rules": [
                {
                    "type": "field",
                    "ip": [
                        "0.0.0.0/8",
                        "10.0.0.0/8",
                        "100.64.0.0/10",
                        "127.0.0.0/8",
                        "169.254.0.0/16",
                        "172.16.0.0/12",
                        "192.0.0.0/24",
                        "192.0.2.0/24",
                        "192.168.0.0/16",
                        "198.18.0.0/15",
                        "198.51.100.0/24",
                        "203.0.113.0/24",
                        "::1/128",
                        "fc00::/7",
                        "fe80::/10"
                    ],
                    "outboundTag": "blocked"
                }
            ]
        }
    }
}
END

    @session.upload!(StringIO.new(server_conf), "/etc/v2ray/config.json")
    @session.execute("/bin/systemctl restart v2ray")

    uuids.each do |uuid|
      client_conf_path = File.join(client_configs_dir, "v2ray_#{uuid}.conf")
      client_conf = <<END
{
    "log": {
        "loglevel": "warning"
    },
    "inbound": {
        "listen": "127.0.0.1",
        "port": 60000,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": true,
            "ip": "127.0.0.1"
        }
    },
    "outbound": {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": "#{@domain}",
                    "port": #{port},
                    "users": [
                        {
                            "id": "#{uuid}",
                            "level": 1,
                            "security": "aes-128-gcm",
                            "alterId": 100
                        }
                    ]
                }
            ]
        }
    },
    "outboundDetour": [
        {
            "protocol": "freedom",
            "settings": {},
            "tag": "direct"
        }
    ],
    "routing": {
        "strategy": "rules",
        "settings": {
            "rules": [
                {
                    "type": "field",
                    "port": "54-79",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "port": "81-442",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "port": "444-65535",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "domain": [
                        "gc.kis.scr.kaspersky-labs.com"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "chinasites",
                    "outboundTag": "direct"
                },
                {
                    "type": "field",
                    "ip": [
                        "0.0.0.0/8",
                        "10.0.0.0/8",
                        "100.64.0.0/10",
                        "127.0.0.0/8",
                        "169.254.0.0/16",
                        "172.16.0.0/12",
                        "192.0.0.0/24",
                        "192.0.2.0/24",
                        "192.168.0.0/16",
                        "198.18.0.0/15",
                        "198.51.100.0/24",
                        "203.0.113.0/24",
                        "::1/128",
                        "fc00::/7",
                        "fe80::/10"
                    ],
                    "outboundTag": "direct"
                },
                {
                    "type": "chinaip",
                    "outboundTag": "direct"
                }
            ]
        }
    }
}
END
      @session.upload!(StringIO.new(client_conf), client_conf_path)
    end
  end

  def common_setup
    @session.execute('apt-get update')
    @session.execute('DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y upgrade')
    @session.execute('apt-get -y install gdebi-core')
  end

  def setup_sysctl
    sysctl_conf = '/etc/sysctl.conf'
    content = <<END
net.ipv6.conf.all.accept_ra = 2
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
END
    @session.upload!(StringIO.new(content), sysctl_conf)
  end

  def default_iface
    @session.capture('ip route | grep default').split(/\s+/)[4]
  end

  def setup_firewall
    firewall_rules = '/etc/iptables.firewall.rules'
    wg_port = @wireguard['port'] || 54321
    v2_port = @v2ray['port'] || 50443
    wg_rule = @wireguard.nil? ? '' : "-A INPUT -p udp --dport #{wg_port} -j ACCEPT"
    v2_rule = @v2ray.nil? ? '' : "-A INPUT -p tcp --dport #{v2_port} -j ACCEPT\n-A INPUT -p udp --dport #{v2_port} -j ACCEPT"
    content = <<END
*filter

-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
#{wg_rule}
#{v2_rule}
-A INPUT -p tcp --dport 53 -j ACCEPT
-A INPUT -p udp --dport 53 -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -j DROP

COMMIT
END
    @session.upload!(StringIO.new(content), firewall_rules)
    script = '/etc/network/if-pre-up.d/firewall'
    content = <<END
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
exit 0
END
    @session.upload!(StringIO.new(content), script)
    @session.execute("chmod +x #{script}")
  end

  def deploy
    check_os
    common_setup
    install_wireguard
    install_v2ray
    setup_sysctl
    setup_firewall
    show_client_config_qr
  end

  def reboot
    begin
      @session.execute('reboot;exit')
    rescue StandardError => e
    end
  end
end

class Deployer
  def initialize
    path = CONFIG_YML
    raise 'config.yml does not exists.' unless File.exists?(path)
    @config = YAML.load(File.open(path).read)
    @domain = @config['domain']
  end

  def run
    config = @config
    on "root@#{@domain}" do
      server = Server.new(self, config)
      begin
        server.deploy
      rescue StandardError => e
        puts e.message
        exit(1)
      else
        server.reboot
      end
    end
  end
end

Deployer.new.run
