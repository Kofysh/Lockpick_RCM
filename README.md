Lockpick RCM
=
Lockpick RCM is a bare metal Nintendo Switch payload that derives encryption keys for use in Switch file handling software like hactool, hactoolnet/LibHac, ChoiDujour, etc. without booting Horizon OS.

Due to changes imposed by firmware 7.0.0, Lockpick homebrew can no longer derive the latest keys. In the boot-time environment however, there is no such limitation.

Usage
=
* It is highly recommended, but not required, to place Minerva on SD from the latest [Hekate](https://github.com/CTCaer/hekate/releases) for best performance, especially while dumping titlekeys - the file and path is `/bootloader/sys/libsys_minerva.bso`
* Launch Lockpick_RCM.bin using your favorite payload injector or chainloader
* Upon completion, keys will be saved to `/switch/prod.keys` and titlekeys to `/switch/title.keys` on SD
* This release bundles the Falcon keygen from [Atmosphère-NX](https://github.com/Atmosphere-NX/Atmosphere)

Mariko-Specific Keys
=
Mariko consoles have several unique keys and protected keyslots. To get your SBK or the Mariko specific keys, you will need to use the `/switch/partialaes.keys` file along with a brute forcing tool such as <https://files.sshnuke.net/PartialAesKeyCrack.zip>. The contents of this file are the keyslot number followed by the result of that keyslot encrypting 16 null bytes. With the tool linked above, enter them in sequence for a given keyslot you want the contents of, for example: `PartialAesKeyCrack.exe <num1> <num2> <num3> <num4>` with the `--numthreads=N` where N is the number of threads you can dedicate to the brute force.

The keyslots are as follows, with names recognized by `hactool`:
* 0-11 - `mariko_aes_class_key_xx` (this is not used by the Switch but is set by the bootrom; hactoolnet recognizes it but it serves no purpose)
* 12 - `mariko_kek` (not unique - this is used for master key derivation)
* 13 - `mariko_bek` (not unique - this is used for BCT and package1 decryption)
* 14 - `secure_boot_key` (console unique - this isn't needed for further key derivation than what Lockpick_RCM does but might be nice to have for your records)
* 15 - Secure storage key (console unique - this is not used on retail or dev consoles and not recognized by any tools)

So if you want to brute force the `mariko_kek`, open your `partialaes.keys` and observe the numbers beneath keyslot 12. Here's an example with fake numbers:
```
12
11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444
```
Then take those numbers and open a command prompt window at the location of the exe linked above and type:
`PartialAesKeyCrack.exe 11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444` and if you're on a powerful enough multicore system, add ` --numthreads=[whatever number of threads]`, ideally not your system's maximum if it's, for example, an older laptop with a low-end dual core CPU. On a Ryzen 3900x with 24 threads this generates a lot of heat but finishes in about 45 seconds.

These keys never change so a brute force need only be conducted once.

This works due to the security engine immediately flushing writes to keyslots which can be written one 32-bit chunk at a time. See: <https://switchbrew.org/wiki/Switch_System_Flaws#Hardware>

Building
=
Install [devkitARM](https://devkitpro.org/) and run `make`.

Massive Thanks to CTCaer!
=
This software is heavily based on [Hekate](https://github.com/CTCaer/hekate). Beyond that, CTCaer was exceptionally helpful in the development of this project, lending loads of advice, expertise, and humor.

License
=
This project is under the GPLv2 license. The Save processing module is adapted from [hactool](https://github.com/SciresM/hactool) code under ISC.

Unnoficial Repo
=
This repository is just a clone of [shchmue](https://github.com/shchmue)'s DMCA'd Lockpick_RCM repository, the changes made to this repository use the source code found in [ReSwitched's discord server](https://reswitched.github.io/discord/)
