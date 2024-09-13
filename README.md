## router.nix

This is my router at the time of writing.

This config is running on an [APU2](https://www.pcengines.ch/apu2.htm).

### Building

Note, there is a magic "secrets" directory which is not checked in, and so this will not successfully build as-is. You'll have to fork it and deal with secrets in your own way.

I flash it with:

```console
$ make
# plug in usb drive
$ cp ./iso/*/*.iso /dev/<usb-device-like-sdb>
```

And then plug the usb-drive into the APU2 box and power cycle it.
It can also `nixos-rebuild switch` to update it in-place on the router.

### Accompanying blog post

Most of the complexity is weird Japanese Internet stuff, namely MAP-E. See [my blog post](https://euank.com/2023/02/22/v6-plus.html) from when I first set this up for more info on that!

### License

[Unlicense](https://en.wikipedia.org/wiki/Unlicense).

I donate all the code in this repository to the public domain, and frankly I'm not sure any of this is creative enough to be considered copyrightable.
