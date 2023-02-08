.PHONY: all
all:
	nix build -o iso '.#nixosConfigurations.rock.config.system.build.isoImage'
