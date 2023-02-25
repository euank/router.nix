{ config, pkgs, inputs, ... }:
{
  imports = [
    "${inputs.nixpkgs}/nixos/modules/installer/cd-dvd/installation-cd-minimal.nix"
    "${inputs.nixpkgs}/nixos/modules/installer/cd-dvd/channel.nix"
  ];

  # Poached from https://dataswamp.org/~solene/2022-08-03-nixos-with-live-usb-router.html
  # Thank you!
  isoImage.squashfsCompression = "zstd -Xcompression-level 5";
  powerManagement.cpuFreqGovernor = "ondemand";
  boot.kernelParams = [ "copytoram" "console=ttyS0,115200n8" ];
  boot.supportedFilesystems = pkgs.lib.mkForce [ "btrfs" "vfat" "xfs" "ntfs" "cifs" ];
  services.irqbalance.enable = true;

  networking.hostName = "rock";
  networking.useNetworkd = false; # one day
  networking.usePredictableInterfaceNames = true;
  # trust LAN
  networking.firewall.trustedInterfaces = [ "enp2s0" ];
  networking.firewall.allowedTCPPorts = [ 22 ];
  security.sudo.wheelNeedsPassword = false;
  services.openssh.enable = true;
  boot.kernel.sysctl = {
    "net.ipv4.conf.all.forwarding" = 1;
    "net.ipv4.conf.default.forwarding" = true;

    "net.ipv6.conf.all.accept_ra" = 1;
    "net.ipv6.conf.enp1s0.accept_ra" = 2;
    "net.ipv6.conf.all.forwarding" = true;
    "net.ipv6.conf.default.forwarding" = true;
  };
  networking.firewall.checkReversePath = "loose";

  # By default, only allow in ssh traffic to our public IP addresses from the
  # internet.
  networking.firewall.extraCommands = ''
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
      unitConfig = {
        Type = "simple";
      };
      serviceConfig = {
        ExecStart = "${pkgs.ngrok}/bin/ngrok tcp --log=stdout --log-level=info --config=${ngrokConfig} --region=jp --remote-addr=1.tcp.jp.ngrok.io:20603 22";
      };
      wantedBy = [ "multi-user.target" ];
    };

  environment.systemPackages = with pkgs; [
    htop
    curl
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
    unitConfig = {
      Type = "simple";
    };
    path = with pkgs; [ iptables iproute2 ];
    serviceConfig = {
      ExecStart = "${pkgs.v6plus-tun}/bin/v6plus-tun setup-linux --wan enp1s0 ${inputs.secrets.ipv6_addr}"; # TODO: stop hardcoding
    };
    wantedBy = [ "multi-user.target" ];
    # setup ipv4 after ipv6 is up
    after = [ "network-online.target" ];
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
      ip -6 rule add from all tab 20 priority 1000
    '';
  };

  services.dhcpd4 = {
    enable = true;
    interfaces = [ "enp2s0" ];
    extraConfig = ''
      option routers 10.57.25.254;
      option domain-name-servers 8.8.8.8;
      default-lease-time 600;
      max-lease-time 7200;
      authoritative;
      subnet 10.57.25.0 netmask 255.255.255.0 {
        range 10.57.25.10 10.57.25.200;
      }
    '';
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
          auto
        }
      }
    '';
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
    ];
  };
}
