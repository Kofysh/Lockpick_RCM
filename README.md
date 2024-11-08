
# 🔓 Lockpick_RCM

Lockpick_RCM is a bare-metal Nintendo Switch payload that extracts encryption keys for use in file handling software like **hactool**, **hactoolnet/LibHac**, **ChoiDujour**, etc., all without booting into Horizon OS. 🚀

> ⚠️ **Note:** Due to changes in firmware 7.0.0 and beyond, the Lockpick homebrew can no longer derive the latest keys. However, this limitation doesn't apply in the boot-time environment, allowing Lockpick_RCM to function properly.

## 🚀 Usage

1. 🗄️ **Recommended** : Place **Minerva** on your SD card for optimal performance, especially when dumping titlekeys. You can get it from the latest [Hekate](https://github.com/CTCaer/hekate/releases) release. Place the file at :
   ```
   /bootloader/sys/libsys_minerva.bso
   ```
2. 🎮 Launch `Lockpick_RCM.bin` using your preferred payload injector or chainloader.
3. 💾 Keys will be saved to:
   - `/switch/prod.keys`
   - `/switch/title.keys` on your SD card.

> This release also includes the Falcon keygen from [Atmosphère-NX](https://github.com/Atmosphere-NX/Atmosphere).

## 🔑 Mariko-Specific Keys

Mariko consoles (Switch V2 and Switch Lite) contain unique keys and protected keyslots. To extract these keys, you will need to use the `/switch/partialaes.keys` file along with a brute-forcing tool like [PartialAesKeyCrack](https://files.sshnuke.net/PartialAesKeyCrack.zip). The process involves :

1. Open `partialaes.keys` and observe the keyslot data.
2. Use the following command format :
   ```
   PartialAesKeyCrack.exe <num1> <num2> <num3> <num4> --numthreads=[N]
   ```
   Replace `[N]` with the number of threads to utilize (not exceeding your CPU's core count).

### 🔍 Keyslots Overview

| Keyslot | Name                         | Notes                                         |
| ------- | ---------------------------- | --------------------------------------------- |
| 0-11    | `mariko_aes_class_key_xx`    | Not used by the Switch (set by bootrom)       |
| 12      | `mariko_kek`                 | Used for master key derivation                |
| 13      | `mariko_bek`                 | Used for BCT and package1 decryption          |
| 14      | `secure_boot_key`            | Console unique (for personal records)         |
| 15      | Secure storage key           | Console unique (not used on retail/dev units) |

**Example:**
```
12
11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444
```

To brute force `mariko_kek`, run :
```
PartialAesKeyCrack.exe 11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444 --numthreads=12
```

> 💡 On a high-performance CPU like the Ryzen 3900x, this process takes about 45 seconds using 24 threads.

🔗 For more details on the hardware flaw utilized : [Switch System Flaws - Hardware](https://switchbrew.org/wiki/Switch_System_Flaws#Hardware)

## 🛠️ Building

1. Install [devkitARM](https://devkitpro.org/).
2. Run :
   ```
   make
   ```

## 🙌 Massive Thanks to CTCaer !

This project owes a lot to [Hekate](https://github.com/CTCaer/hekate), and special thanks go to **CTCaer** for his valuable advice, expertise, and humor throughout the development process. 🎉

## 📜 License

Lockpick_RCM is licensed under the **GPLv2**. The save processing module is adapted from [hactool](https://github.com/SciresM/hactool), licensed under ISC.

## ⚠️ Unofficial Repository

This repository is a clone of the DMCA'd Lockpick_RCM by [shchmue](https://github.com/shchmue). The modifications here are based on the source code shared on the [ReSwitched Discord server](https://reswitched.github.io/discord/). 
