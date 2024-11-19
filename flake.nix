{
  description = "My router";

  inputs = {
    nixpkgs.url = "github:euank/nixpkgs/ndppdcmpcpp-2024-11-19";
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
        rock = nixpkgs.lib.nixosSystem {
          system = "x86_64-linux";
          inherit pkgs;
          specialArgs = { inherit inputs; };
          modules = [ ./configuration.nix ];
        };
      };
    };
}
