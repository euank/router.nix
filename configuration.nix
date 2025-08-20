{ config, pkgs, inputs, ... }:
let
  # hack: this is a port I happen to know is within my ipv4 map-E range, but in
  # general this won't necessarily work for another map-E setup. I mean, it'll
  # work over ipv6, just not ipv4 on other setups.
  wgPort = 64512;
  sshPort = 64513;
  kPort1 = 64514;
  kPort2 = 64515;
  kPort1' = 64516;
  kPort2' = 64517;
in
{
  disabledModules = [ "services/networking/ndppd.nix" ];
  imports = [
    "${inputs.nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
    "${inputs.nixpkgs}/nixos/modules/installer/cd-dvd/channel.nix"

    "${inputs.nixpkgs-ndppd}/nixos/modules/services/networking/ndppd.nix"
  ];

  boot.kernelPackages = pkgs.linuxPackages_latest;

  # Poached from https://dataswamp.org/~solene/2022-08-03-nixos-with-live-usb-router.html
  # Thank you!
  isoImage.squashfsCompression = "zstd -Xcompression-level 5";
  powerManagement.cpuFreqGovernor = "ondemand";
  boot.kernelParams = [ "console=ttyS0,115200n8" ];
  boot.supportedFilesystems = pkgs.lib.mkForce [ "btrfs" "vfat" "xfs" "ntfs" "cifs" ];
  services.irqbalance.enable = true;

  networking.hostName = "rock";
  networking.useNetworkd = false; # one day
  networking.usePredictableInterfaceNames = true;
  # trust LAN
  networking.firewall.trustedInterfaces = [ "enp2s0" "wg0" "wg1" ];
  networking.firewall.allowedTCPPorts = [ 22 ];
  networking.firewall.allowedUDPPorts = [
    wgPort
    kPort1 kPort1'
    kPort2 kPort2'
  ];
  security.sudo.wheelNeedsPassword = false;
  services.openssh.enable = true;
  services.openssh.ports = [ 22 sshPort ];
  boot.kernel.sysctl = {
    "net.ipv4.conf.all.forwarding" = 1;
    "net.ipv4.conf.default.forwarding" = true;

    "net.ipv6.conf.all.accept_ra" = 1;
    "net.ipv6.conf.enp1s0.accept_ra" = 2;
    "net.ipv6.conf.all.forwarding" = true;
    "net.ipv6.conf.default.forwarding" = true;
  };
  networking.firewall.checkReversePath = "loose";

  services.avahi = {
    enable = true;
    nssmdns4 = true;
    hostName = "router";
    allowInterfaces = [ "enp2s0" "wg0" "wg1" ];
    publish = {
      enable = true;
      addresses = true;
      domain = true;
      userServices = true;
    };
  };

  # By default, only allow in ssh traffic to our public IP addresses from the
  # internet.
  networking.firewall.extraCommands = ''
    # Handle a special whitelisted port
    iptables -t nat -A PREROUTING -i ip4tun0 -p udp --dport ${toString kPort1} -j DNAT --to-destination 10.57.25.18:${toString kPort1}
    iptables -t nat -A PREROUTING -i ip4tun0 -p udp --dport ${toString kPort1'} -j DNAT --to-destination 10.57.25.25:${toString kPort1'}

    ip6tables -N forwarding-rules
    ip6tables -A FORWARD -j forwarding-rules

    # Okay to let traffic out
    ip6tables -A forwarding-rules -i enp2s0 -o enp1s0 -j ACCEPT
    # Only let responses back in
    ip6tables -A forwarding-rules -m state --state RELATED,ESTABLISHED -j ACCEPT
    # Except for whitelisted ssh ports
    ip6tables -A forwarding-rules -i enp1s0 -o enp2s0 -p tcp -m tcp --dport 22 -j ACCEPT
    ip6tables -A forwarding-rules -i enp1s0 -o enp2s0 -p tcp -m tcp --dport 22 -j ACCEPT

    # https://www.rfc-editor.org/rfc/rfc4890#section-4.3.5
    ip6tables -A forwarding-rules -p ipv6-icmp -m icmp6 --icmpv6-type 138 -j DROP
    ip6tables -A forwarding-rules -p ipv6-icmp -m icmp6 --icmpv6-type 139 -j DROP
    ip6tables -A forwarding-rules -p ipv6-icmp -m icmp6 --icmpv6-type 140 -j DROP
    # And we want the rest of the icmp6 traffic
    ip6tables -A forwarding-rules -p ipv6-icmp -j ACCEPT

    # Nothing else
    ip6tables -A forwarding-rules -j DROP
  '';
  networking.firewall.extraStopCommands = ''
    # Inverse of the above
    ip6tables -F forwarding-rules
    ip6tables -D FORWARD -j forwarding-rules
    ip6tables -X forwarding-rules

    iptables -t nat -D PREROUTING -i enp1s0 -p udp --dport ${toString kPort1} -j DNAT --to-destination 10.57.25.18:${toString kPort1}
    iptables -t nat -D PREROUTING -i enp1s0 -p udp --dport ${toString kPort1'} -j DNAT --to-destination 10.57.25.25:${toString kPort1'}
    ip6tables -t nat -D PREROUTING -i enp1s0 -p udp --dport ${toString kPort2} -j DNAT --to-destination 10.57.25.18:${toString kPort2}
    ip6tables -t nat -D PREROUTING -i enp1s0 -p udp --dport ${toString kPort2'} -j DNAT --to-destination 10.57.25.25:${toString kPort2'}
  '';

  systemd.services.ngrok-ssh =
    let
      ngrokConfig = pkgs.writeText "conf.yml" ''
        version: 2
        authtoken: ${inputs.secrets.ngrok_authtoken}
        crl_noverify: true
      '';
    in
    {
      enable = true;
      description = "ngrok ssh";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.ngrok}/bin/ngrok tcp --log=stdout --log-level=info --config=${ngrokConfig} --region=jp --remote-addr=1.tcp.jp.ngrok.io:20603 22";
      };
      wantedBy = [ "multi-user.target" ];
    };

  environment.systemPackages = with pkgs; [
    curl
    git
    htop
    ethtool
    vim
  ];

  networking = {
    # WAN
    interfaces.enp1s0 = {
      useDHCP = true;
    };
    # LAN
    interfaces.enp2s0 = {
      useDHCP = false;
      ipv4.addresses = [{
        address = "10.57.25.254";
        prefixLength = 24;
      }];
    };
    # Spare
    interfaces.enp3s0 = {
      useDHCP = false;
    };
    # We setup more specific nat below
    nat.enable = false;
    dhcpcd.persistent = true;
  };

  # And finally, the 4in6 tunnel
  systemd.services.v4-plus = {
    enable = true;
    description = "setup v4 tunnel";
    path = with pkgs; [ iptables iproute2 ];
    serviceConfig = {
      Type = "simple";
      ExecStart = ''
        ${pkgs.v6plus-tun}/bin/v6plus-tun setup-linux \
          --add-ipv4-addr \
          --no-snat-ipv4-ports ${toString wgPort} \
          --no-snat-ipv4-ports ${toString sshPort} \
          --no-snat-ipv4-ports ${toString kPort1} \
          --no-snat-ipv4-ports ${toString kPort1'} \
          --no-snat-ipv4-ports ${toString kPort2} \
          --no-snat-ipv4-ports ${toString kPort2'} \
          --wan enp1s0 \
          ${inputs.secrets.ipv6_addr}
      '';
      Restart = "on-failure";
      RestartSec = 10;
    };
    wantedBy = [ "multi-user.target" ];
    after = [
      "network-online.target"
      "network-addresses-enp1s0.service"
      "network-addresses-enp2s0.service"
    ];
    requires = [ "network-online.target" ];
  };

  systemd.services.v6-lan-route = {
    enable = true;
    description = "setup some extra v6 rules";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    requires = [ "network-online.target" ];
    path = with pkgs; [ iproute2 ];
    script = ''
      ip -6 r replace ${inputs.secrets.ipv6_prefix} dev enp2s0 tab 20
      if [[ "$(ip -6 rule list tab 20 priority 1000)" == "" ]]; then
        ip -6 rule add from all tab 20 priority 1000
      fi
    '';
  };

  services.kea.dhcp4 = {
    enable = true;
    settings = {
      interfaces-config = {
        interfaces = [ "enp2s0" ];
        # crashloop to victory if we race
        service-sockets-require-all = true;
      };
      lease-database = {
        name = "/var/lib/kea/dhcp4.leases";
        persist = true;
        type = "memfile";
      };
      valid-lifetime = 7200;
      subnet4 = [
        {
          id = 1;
          subnet = "10.57.25.0/24";
          pools = [
            {
              pool = "10.57.25.10 - 10.57.25.200";
            }
          ];
          option-data = [
            {
              name = "routers";
              data = "10.57.25.254";
            }
            {
              name = "domain-name-servers";
              data = "8.8.8.8";
            }
          ];
          reservations =
            if inputs.secrets ? staticIPs then
              (
                pkgs.lib.mapAttrsToList (mac: ip: { hw-address = mac; ip-address = ip; }) inputs.secrets.staticIPs
              ) else [ ];
        }
      ];
    };
  };
  systemd.services.kea-dhcp4-server = {
    after = [ "v4-plus.service" ];
    wants = [ "v4-plus.service" ];
    serviceConfig = {
      Restart = "on-failure";
      RestartSec = 5;
    };
  };

  services.radvd = {
    enable = true;
    config = ''
      interface enp2s0
      {
        AdvSendAdvert on;
        MaxRtrAdvInterval 30;
        prefix ${inputs.secrets.ipv6_prefix}
        {
          AdvOnLink on;
          AdvAutonomous on;
        };
        RDNSS 2001:4860:4860::8888
        {
        };
      };
    '';
  };

  services.ndppd = {
    enable = true;
    configFile = pkgs.writeText "ndppd.conf" ''
      route-ttl 1000
      proxy enp1s0 {
        router no
        ttl 3000
        autowire yes
        rule ${inputs.secrets.ipv6_prefix} {
          iface enp2s0
          autovia yes
        }
      }
    '';
  };
  # Try waiting for both devices to be ready before proxying stuff
  systemd.services.ndppd.serviceConfig.After = [
    "network-addresses-enp1s0.service"
    "network-addresses-enp2s0.service"
  ];
  systemd.services.ndppd.serviceConfig.Restart = "always";
  systemd.services.ndppd.serviceConfig.RestartSec = 10;

  networking.wireguard.interfaces = {
    wg0 = {
      # smaller mtu because the ipip tunnel shaves some off the top too
      mtu = 1380;
      ips = [ "10.104.0.1/16" ];
      listenPort = wgPort;
      postSetup = ''
        ${pkgs.iptables}/bin/iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT
        ${pkgs.iptables}/bin/iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      '';
      postShutdown = ''
        ${pkgs.iptables}/bin/iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT
        ${pkgs.iptables}/bin/iptables -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
      '';
      # pubkey +pLrsgXAn4rH4e+gQWR03n02o2vDNiL1sDOXEYSrmGg=
      privateKey = inputs.secrets.wireguard.privKey;
      peers = [
        {
          publicKey = "s1P4uQwGt/qxSZotHXmQohdHVCC9voRWtypevBVsu1o=";
          allowedIPs = [ "10.104.20.0/25" ];
        }
        {
          publicKey = "wvrB4bKlRHj+vxLk6TbzTGjylWesEFrzwzwDvEhTNAI=";
          allowedIPs = [ "10.104.20.254/32" ];
        }
        {
          publicKey = "BWP17DD9Zz0fnYvfrST+xVVYvaPXWV3+NyMZ1YfNaz0=";
          allowedIPs = [ "10.104.21.0/25" ];
        }
        {
          publicKey = "b5CRCCnpyMwdNlAR3hvJLEPxKyHM0xU+5krClAyL7jY=";
          allowedIPs = [ "10.104.6.1/32" ];
        }
        {
          publicKey = "TMRycR9pgXCfULdvZSTLR8yolv4CD1pOU9clAg3MazM=";
          allowedIPs = [ "10.104.6.2/32" ];
        }
        {
          publicKey = "J7IqhF9tx8fbOp1LkPuhowbVgt0zm0GCp05gH9HCJR4=";
          allowedIPs = [ "10.104.6.3/32" ];
        }
        {
          publicKey = "6BVb0BUb5kBP5SOmxGRO36iZnnRZpsc+q2+EMNorFV8=";
          allowedIPs = [ "10.104.6.4/32" ];
        }
      ];
    };

    # Used for some stuff
    wg1 = {
      ips = [ "10.101.107.2/24" ];
      privateKey = inputs.secrets.wireguard.privKey;
      allowedIPsAsRoutes = false;

      # Something like the following will vpn a single device
      #
      #     ip rule add from <internal-ip> lookup 24
      #
      # Be aware of ipv6 of course
      postSetup = ''
        ${pkgs.iproute2}/bin/ip route add default dev wg1 tab 24 || true
        ${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE || true
      '';
      postShutdown = ''
        ${pkgs.iproute2}/bin/ip route del default dev wg1 tab 24 || true
        ${pkgs.iptables}/bin/iptables -t nat -D POSTROUTING -o wg1 -j MASQUERADE || true
      '';
      peers = [
        {
          publicKey = "fHDk+22yah18ytcDFl97kVucKkdhvW3Ykx9qX2DdxUU=";
          allowedIPs = [ "0.0.0.0/0" ];
          endpoint = inputs.secrets.wireguard.wg1Endpoint;
          persistentKeepalive = 25;
        }
      ];
    };
  };

  time.timeZone = "Asia/Tokyo";

  users.mutableUsers = false;
  users.users.esk = {
    isNormalUser = true;
    extraGroups = [ "sudo" "wheel" ];
    openssh.authorizedKeys.keys = [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyeivCOXMLvMzKvZjPzNSqD8kvkbsI/Ecdxe7V7HZDG8AfliS68frOZI5pl0uqfBet80e5qH/njDvdfKpKuBiAgUZcBz1+LGdrCr+Tn8Bi0ypu+xSpjJjPT0fVgD9qk0lv5TnUmqZD/BZShQjlp6T0MfETSbGppTxRRZIS2CgjO230fktZST8GUJBX/G0HVupqVdbORVdBkbEx4XfJLrmI3HSuA2drlImhCegrByg8r6k2Q/256myWri8Q2X0bVIg93FqcuLGvngGL8kJinwo/zRPo5ucfH0DWsQWtHo6ayx2FycMsCmd56ZU+FH9PBy73ki4ACqsaGh+T8silAR5R"
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMdxqFTG7bPey17ZWg6LbonqASSNJnlmdMg3yiYPuNu6/b4Ffe4iycGAwVl/ODKnEzLZ2aWUhiVrLMv4Z6vml3/l/qU3PPeQRe+TY0afXLbT05xDG2HS/y5SE/6qoynKb2FzJ8YCpI3xdoJ3E4L5+a5vZ1yjknaFcHcL0/g5GCsKo0QpO6dH9Tz+W36Ua/kGXmqMzDaOraXLvTc2TBJ4Mm/CRy6zL773V4GE5e+w4MxdYGpaGZ2EaKw37xFAyx2lH2/RbRt+qTsvGOjfhXuMyOEtsrDEkM7mbRdjuC8WzlutTrDESRJuVAu47HEZjMKCaQ05wgI/LYS3CeolorGDf9tahnjS5s0x7X+NIRkEA0qgpxUwr5T9Z7JKWIIOV90Rbu6CFEfhldNtfA5uD8RLufIiiQTsTZmHjHaPWi98iphb+wMpy8yB4lPPzoWfSuofPVcWaLFoFzGwKkP38XLyeKXEyUgGJPTLPLkGNjQgTBqZlOTL06UR8GNKPtWo5dMCvsFuz0+u34LaeyNg+2i7gvhWZakDZ1EAqWdtj6A+8oAlIEa04OR09xlfdjA9BMA4xGyq9sOKn99tV5qTIZl3X+MIxxPUm0TYXulM4kByeKROAvQhgwSUJAE63qVddBnl+PAsUZPREl8l/ccuytZIlnDn2RY0LlIXGYb0tIEykSqw=="
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCyFcdo10FvG1lxiUKjccK2agmIIm13w0XmtftjI36q+7tg6ULrbFRdk/XITucTfSet/0y9Kup8QJM00i8k9EGD5SGcULhDX6p/mc0YTI1DeOHauAU3y7hlsE0a13sm5kg7XZ1dDqb5nY+8I6ZjHc5FlbjatAKHOSosljjIeOSvgg/tKJGf8qna4pzlgfhN4bf8jbK4ZJ6JoTVD9ulQqKKcwLdJFIxxKR4VxXVxGHiH8dvP3oPzhQ6W9GAc0yfBl8kIxJdzvEd5h7vX9b93ZFWolkkZYpyxbvapeeLmNX4e5TexWPUU1kT7jIi/rvTrSow5iYGu5rgwgqy6Ey37jhpQKQUgwkLPH1mt/9vg4WlpbPEk0TihDmW0yJ8CwHetZAs4cjSbiuMGopBf2rCEIrjyflKIiy/Of7MVp3NVEPVDOu3VEH/khxrHR5KC9XKOg4jhcsQBj0t+i1iJCmi981sXzXLHmmXZMNlcf0jFSG4TwApyc1+hJIBladsSZ12mLY1lFCTx/Yx3ztoNPqGPLAkNYuj3z50jL/Jdj2oVNcQqNpxb6bHmW416LcuUGQ9DSIJUJLxmv/CXW5Wpepm30KTumJSy6G6bBCe4b+Gw2g74K6uwjEaX2uGXNJvRNE+ftDf23fy1orO3HLncY23Du/R6iDcMj/coMMlkAES1AdxEFw=="
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCKqFuQdr7H2xwTM1p/CEbFvZ7oVPX1fjwYkJOv50O70a+NXaAs9Eg5Cnyhs0pKLwogMp3AZsdkVPyUtZIuShFw/e7DAz6Eo4kdXoU8oMhYqWEAFfTF+m/uCWoesPQK+6XQute7DkqR+0A+tgc7dNM9TYZyXdNNl/corxchGH+K0S+ENdcM8j4qllBxJE6GtlFQgMzN3URW2g6lTTGD8HoICl+ajfuLGBsg7O8UZHM9qsLC0K4Ej23FF9GIMEYlnSentVZo4o1hj/xTzsiKhl1EFvP8oo22vYkebQRX0XhrNCehouQYrmM0fSS7+m9UjQK9jWaXBZ+Z5r/ppoJzQ80p"
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDbIYGM+sFgB3v1dxIhZeSQpQvH4sCnSm0yIshu17WvgBYR0T0IAtean1/RFlTaPwP1qlgiPiQo0gobUUS6Ahi2tpHa9MLkZTlY5DT0qOJJYj7a4mnErxpk6GZjEVfSNcopk/8iFYVgQlFr9YAJFTkZV+gJC0zeQHhHwdD3n1NhFVhbvCcfeP6PYBvnhS7v6g8IruWixtUBgcrs2jKCfbwYdnUua4+UZ76+sJOba9qIVwdXEO2Sc3pVXeeL81F6KGCc2BMtNa8tJbX5NMcQmNyywKvRhP3JueByP1C67fh887qZR/FJ5lvzxUd07DOVBe/tFJAb1gffy6k9IYwW++/jDTjsBZdz0bW7lazDgwckazt2g3Xphn3Nx2T/CImCLm+ILeAm6X3sfbFHbk48pZmZKAjsP1gbg5jC+mm3TmgrnMBTMO1ctuWDRL1K5zICxMKUVcoZ0C+pJufg84w+xX2ZST7kRox5qXa9Ge1aQ14o17VSkjK45SoM3j0fmjNBeOk="
    ];
  };

  nix.settings.trusted-users = [ "root" "esk" ];

}
