**Lockpick RCM**
=
Lockpick RCM est un payload bare metal pour Nintendo Switch qui dérive des clés de cryptage pour une utilisation dans des logiciels de gestion de fichiers Switch comme hactool, hactoolnet/LibHac, ChoiDujour, etc., sans démarrer Horizon OS.

En raison des changements imposés par le firmware 7.0.0, le homebrew Lockpick ne peut plus dériver les dernières clés. Cependant, dans l'environnement de démarrage, il n'y a pas de telle limitation.

**Utilisation**
=
* Il est fortement recommandé, mais non obligatoire, de placer Minerva sur la SD à partir de la dernière version de [Hekate](https://github.com/CTCaer/hekate/releases) pour obtenir les meilleures performances, en particulier lors de l'extraction des clés de titre - le fichier et le chemin sont `/bootloader/sys/libsys_minerva.bso`
* Lancez Lockpick_RCM.bin en utilisant votre injecteur de payload ou chargeur de chaîne préféré
* À la fin, les clés seront enregistrées dans `/switch/prod.keys` et les clés de titre dans `/switch/title.keys` sur la SD
* Cette version inclut le générateur de clés Falcon de [Atmosphère-NX](https://github.com/Atmosphere-NX/Atmosphere)

**Clés spécifiques à Mariko**
=
Les consoles Mariko ont plusieurs clés uniques et slots de clés protégés. Pour obtenir votre SBK ou les clés spécifiques à Mariko, vous devrez utiliser le fichier `/switch/partialaes.keys` avec un outil de force brute tel que [PartialAESKeyCrack](https://files.sshnuke.net/PartialAesKeyCrack.zip). Le contenu de ce fichier est le numéro du slot de clé suivi du résultat de ce slot de clé chiffrant 16 octets nuls. Avec l'outil lié ci-dessus, entrez-les en séquence pour un slot de clé donné dont vous voulez les contenus, par exemple : `PartialAesKeyCrack.exe <num1> <num2> <num3> <num4>` avec `--numthreads=N` où N est le nombre de threads que vous pouvez consacrer à la force brute.

Les slots de clé sont les suivants, avec les noms reconnus par `hactool` :
* 0-11 - `mariko_aes_class_key_xx` (cela n'est pas utilisé par la Switch mais est défini par le bootrom ; hactoolnet le reconnaît mais cela ne sert à rien)
* 12 - `mariko_kek` (non unique - utilisé pour la dérivation des clés principales)
* 13 - `mariko_bek` (non unique - utilisé pour le décryptage BCT et package1)
* 14 - `secure_boot_key` (unique à la console - ce n'est pas nécessaire pour la dérivation des clés au-delà de ce que fait Lockpick_RCM mais peut être utile pour vos archives)
* 15 - Clé de stockage sécurisé (unique à la console - non utilisée sur les consoles de détail ou de développement et non reconnue par les outils)

Donc, si vous souhaitez effectuer une force brute sur le `mariko_kek`, ouvrez votre `partialaes.keys` et observez les numéros sous le slot de clé 12. Voici un exemple avec des numéros fictifs :
```
12
11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444
```
Puis prenez ces numéros et ouvrez une fenêtre de commande à l'emplacement de l'exe lié ci-dessus et tapez :
`PartialAesKeyCrack.exe 11111111111111111111111111111111 22222222222222222222222222222222 33333333333333333333333333333333 44444444444444444444444444444444` et si vous êtes sur un système multicœur suffisamment puissant, ajoutez ` --numthreads=[nombre de threads]`, idéalement pas le maximum de votre système si c'est, par exemple, un ancien portable avec un CPU double cœur bas de gamme. Sur un Ryzen 3900x avec 24 threads, cela génère beaucoup de chaleur mais se termine en environ 45 secondes.

Ces clés ne changent jamais, donc une force brute n'a besoin d'être effectuée qu'une seule fois.

Cela fonctionne en raison du moteur de sécurité qui vide immédiatement les écritures dans les slots de clé, qui peuvent être écrites un morceau de 32 bits à la fois. Voir : [Switchbrew](https://switchbrew.org/wiki/Switch_System_Flaws#Hardware)

**Compilation**
=
Installez [devkitARM](https://devkitpro.org/) et exécutez `make`.

**Un grand merci à CTCaer !**
=
Ce logiciel est fortement basé sur [Hekate](https://github.com/CTCaer/hekate). En outre, CTCaer a été exceptionnellement utile dans le développement de ce projet, offrant de nombreux conseils, expertise et humour.

**Licence**
=
Ce projet est sous la licence GPLv2. Le module de traitement des sauvegardes est adapté du code de [hactool](https://github.com/SciresM/hactool) sous ISC.

**Dépôt non officiel**
=
Ce dépôt est simplement un clone du dépôt DMCA'd Lockpick_RCM de [shchmue](https://github.com/shchmue), les modifications apportées à ce dépôt utilisent le code source trouvé sur [le serveur Discord de ReSwitched](https://reswitched.github.io/discord/)

---
