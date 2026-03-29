# SessionRouter

[Español](readme_es.md) [Русский](readme_ru.md) [Français](readme_fr.md)

SessionRouter est l'implementation de référence du LLARP (Low Latency Anonymous Routing Protocol, protocole de routage anonyme à latence faible), un protocole de routage en oignon de couche 3.

Vous pouvez en savoir plus sur le haut niveau de conception du LLARP [ici](docs/)

[![Build Status](https://ci.oxen.rocks/api/badges/session-foundation/session_router/status.svg?ref=refs/heads/dev)](https://ci.oxen.rocks/session-foundation/session_router)

## Installer

Si vous souhaitez simplement installer SessionRouter sans avoir à le compiler vous-même, nous vous proposons plusieurs options de plates-formes d'exécution :

Tier 1:

* [Linux](#linux-install)
* [Android](#apk-install)

Tier 2:

* [Windows](#windows-install)
* [MacOS](#mac-install)
* [FreeBSD](#freebsd-install)

Plateformes actuellement non supportées : (des mainteneurs sont les bienvenus)

* Apple iPhone 
* Homebrew
* \[Insérez ici le gestionnaire de paquets Windows à la mode ce mois-ci.\]

## Construction

Packets necessaires pour construire:

* Git
* CMake
* C++ 17 capable C++ compilateur
* libuv >= 1.27.0
* libsodium >= 1.0.18
* libssl (pour session_router-bootstrap)
* libcurl (fpour session_router-bootstrap)
* libunbound
* libzmq
* cppzmq
* sqlite3

### Linux <span id="linux-install" />

Vous n'avez pas besoin de construire les paquets à partir des sources si vous êtes sous debian ou ubuntu car nous avons des dépôts apt avec des paquets session_router pré-construits sur `deb.oxen.io` ou `rpm.oxen.io`.

Vous pouvez installer les paquets debian en utilisant :

    $ sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
    $ echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
    $ sudo apt update
    $ sudo apt install session_router

Si vous voulez construire session_router à partir des sources :

    $ sudo apt install build-essential cmake git libcap-dev pkg-config automake libtool libuv1-dev libsodium-dev libzmq3-dev libcurl4-openssl-dev libevent-dev nettle-dev libunbound-dev libsqlite3-dev libssl-dev nlohmann-json3-dev
    $ git clone --recursive https://github.com/session-foundation/session_router
    $ cd session_router
    $ mkdir build
    $ cd build
    $ cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
    $ make -j$(nproc)
    $ sudo make install

#### Arch Linux <span id="mom-cancel-my-meetings-arch-linux-broke-again" />

En raison de [circonstances indépendantes de notre volonté](https://github.com/session-foundation/session_router/discussions/1823) un `PKGBUILD` fonctionnel peut être trouvé [ici](https://raw.githubusercontent.com/session-foundation/session_router/makepkg/contrib/archlinux/PKGBUILD).

#### Compilation croisée pour Linux <span id="linux-cross" />

les autres architectures actuellement supportées :

* aarch64-linux-gnu
* arm-linux-gnueabihf
* mips-linux-gnu
* mips64-linux-gnuabi64
* mipsel-linux-gnu
* powerpc64le-linux-gnu

installer la chaîne d'outils (la suivante est pour `aarch64-linux-gnu`, vous pouvez fournir votre propre chaîne d'outils si vous voulez)

    $ sudo apt install g{cc,++}-aarch64-linux-gnu

construire pour une ou plusieurs architectures :

    $ ./contrib/cross.sh arch_1 arch_2 ... arch_n

### MacOS <span id="mac-install" />

SessionRouter ~~est~~ sera disponible sur l'App store d'Apple.

La compilation du code source de SessionRouter par les utilisateurs finaux n'est pas supportée ou autorisée par apple sur leurs plateformes, voir [ceci](contrib/macos/README.txt) pour plus d'informations. Si vous trouvez cela désagréable, envisagez d'utiliser une plateforme qui permet la compilation à partir des sources.

### Windows <span id="windows-install" />

Vous pouvez obtenir la dernière version stable de Windows à l'adresse https://session_router.org/ ou consulter la [page des versions sur github] (https://github.com/session-foundation/session_router/releases).


les compilation automatique de nuit pour les courageux ou les impatients peuvent être trouvées à partir de notre pipeline CI [ici](https://oxen.rocks/session-foundation/session_router/)

#### Construire les paquets sur Windows <span id="win32-cross" />

les compilations Windows sont des compilations croisées à partir de debian/ubuntu linux

exigences de construction supplémentaires:

* nsis
* cpack

configuration:

    $ sudo apt install build-essential cmake git pkg-config mingw-w64 nsis cpack automake libtool
    $ sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
    $ sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix

building:

    $ git clone --recursive https://github.com/session-foundation/session_router
    $ cd session_router
    $ ./contrib/windows.sh

### FreeBSD <span id="freebsd-install" />

Currently has no VPN Platform code, see #1513

construction:

    $ pkg install cmake git pkgconf
    $ git clone --recursive https://github.com/session-foundation/session_router
    $ cd session_router
    $ mkdir build
    $ cd build
    $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DSTATIC_LINK=ON -DBUILD_STATIC_DEPS=ON ..
    $ make

installation (root):

    # make install
    
### Android <span id="apk-install" />

Nous avons un APK Android pour le VPN session_router via l'API VPN android. 

A venir sur F-Droid quand cela arrivera. [[issue]](https://github.com/session-foundation/session_router-flutter-app/issues/8)

* [code source](https://github.com/session-foundation/session_router-flutter-app)
* [CI builds](https://oxen.rocks/session-foundation/session_router/)

## Usage

### Debian / Ubuntu paquets <span id="systemd-linux-usage" />

Lorsque vous installez le paquet debian, les étapes suivantes ne sont pas nécessaires car il est déjà en cours d'exécution et prêt à être utilisé.
prêt à être utilisé.  Vous pouvez l'arrêter/démarrer/redémarrer en utilisant `systemctl start session_router`, `systemctl stop
session_router`, etc.

### Exécution sur Linux (sans debs) <span id="arcane-linux-usage" />

**NE PAS EXECUTER EN TANT QUE ROOT**, exécutez en tant qu'utilisateur normal.

mettre en place les configurations initiales:

    $ session_router -g
    $ session_router-bootstrap

après avoir créé la configuration par défaut, exécutez-la:

    $ session_router

Cela nécessite que le binaire ait les capacités appropriées, ce qui est généralement défini par `make install` sur le binaire. Si vous avez des erreurs concernant les permissions d'ouvrir une nouvelle interface, cela peut être résolu en utilisant :

    $ sudo setcap cap_net_admin,cap_net_bind_service=+eip /usr/local/bin/session_router


----

# License

Ce programme est un logiciel libre : vous pouvez le redistribuer et/ou le modifier selon les termes de la Licence Publique Générale GNU telle que publiée par la Free Software Foundation, soit la version 3 de la Licence, soit (au choix) toute version ultérieure.

```
Copyright © 2018-2022 The Oxen Project
Copyright © 2018-2022 Jeff Becker
Copyright © 2018-2020 Rick V. (Historical Windows NT port and portions)
