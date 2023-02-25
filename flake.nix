{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:euank/nixpkgs/ndppd-debug-2";
    v6plus-tun.url = "github:euank/v6plus-tun";

    # Magic unimportable things
    secrets.url = "path:/home/esk/dev/router.nix/secrets";
  };

  outputs = { self, nixpkgs, ... }@inputs:
    let
      pkgs = import nixpkgs rec {
        system = "x86_64-linux";
        config = { allowUnfree = true; };
        overlays = [
          (prev: final: {
            v6plus-tun = inputs.v6plus-tun.packages.${system}.default;
          })
        ];
      };
    in
    {
      formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.nixpkgs-fmt;
      nixosConfigurations = {
        rock = nixpkgs.lib.nixosSystem rec {
          system = "x86_64-linux";
          inherit pkgs;
          specialArgs = { inherit inputs; };
          modules = [ ./configuration.nix ];
        };
      };
    };
}
