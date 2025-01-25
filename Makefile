.PHONY: iso

iso:
	nix build -o iso '.#nixosConfigurations.rock.config.system.build.isoImage'
