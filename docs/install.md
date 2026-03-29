# Installing

If you are simply looking to install Session Router and don't want to compile it yourself we provide several options for platforms to run on:

Tier 1:

* [Linux](#linux-install)
* [Windows](#windows-install)
* [MacOS](#macos-install)

Tier 2:

* [FreeBSD](#freebsd-install)

Currently Unsupported Platforms: (maintainers welcome)

* [Android](#apk-install)
* Apple iPhone 
* Homebrew
* \[Insert Flavor of the Month windows package manager here\]


## Official Builds

### Windows / MacOS <span id="windows-install" />  <span id="macos-install" />

You can get the latest stable release for Session Router on windows or macos from https://session_router.org/ or check the [releases page on github](https://github.com/session-foundation/session-router/releases).

### Linux <span id="linux-install" />

You do not have to build from source if you do not wish to, we provide [apt](#deb-install) and [rpm](#rpm-install) repos.

#### APT Repository <span id="deb-install" />

You can install debian packages from `deb.oxen.io` by adding the apt repo to your system.

    $ sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
    $ echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
    
This apt repo is also available via Session Router at `http://deb.loki`

Once added you can install Session Router with:

    $ sudo apt update
    $ sudo apt install session-router

When running from debian package the following steps are not needed as it is already running and ready to use. You can stop/start/restart it using `systemctl start session-router`, `systemctl stop session-router`, etc.

#### RPM <span id="rpm-install" />

We also provide an RPM repo, see `rpm.oxen.io`, also available on Session Router at `rpm.loki`
    
## Bleeding Edge dev builds <span id="ci-builds" />

automated builds from dev branches for the brave or impatient can be found from our CI pipeline [here](https://oxen.rocks/session-foundation/session-router/). (warning: these nightly builds may or may not consume your first born child.)

## Building

Build requirements:

* Git
* CMake
* C++ 20 capable C++ compiler (gcc 12+ or clang 15+)
* libsodium >= 1.0.18
* libevent >= 2.1
* libzstd >= 1.3
* libunbound

### Linux Compile

If you want to build from source: <span id="linux-compile" />

    $ sudo apt install build-essential cmake git libcap-dev pkg-config automake libtool libuv1-dev libsodium-dev libzmq3-dev libcurl4-openssl-dev libevent-dev nettle-dev libunbound-dev libssl-dev nlohmann-json3-dev
    $ git clone --recursive https://github.com/session-foundation/session-router
    $ cd session-router
    $ mkdir build
    $ cd build
    $ cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF
    $ make -j$(nproc)
    $ sudo make install

set up the initial configs:

    $ session-router -g
    $ session-router-bootstrap

after you create default config, run it:

    $ session-router

This requires the binary to have the proper capabilities which is usually set by `make install` on the binary. If you have errors regarding permissions to open a new interface this can be resolved using:

    $ sudo setcap cap_net_admin,cap_net_bind_service=+eip /usr/local/bin/session-router


#### Arch Linux <span id="mom-cancel-my-meetings-arch-linux-broke-again" />

Due to [circumstances beyond our control](https://github.com/session-foundation/session-router/discussions/1823) a working `PKGBUILD` can be found [here](https://raw.githubusercontent.com/session-foundation/session-router/makepkg/contrib/archlinux/PKGBUILD).

#### Cross Compile For Linux <span id="linux-cross" />

current cross targets:

* aarch64-linux-gnu
* arm-linux-gnueabihf
* mips-linux-gnu
* mips64-linux-gnuabi64
* mipsel-linux-gnu
* powerpc64le-linux-gnu

install the toolchain (this one is for `aarch64-linux-gnu`, you can provide your own toolchain if you want)

    $ sudo apt install g{cc,++}-aarch64-linux-gnu

build 1 or many cross targets:

    $ ./contrib/cross.sh arch_1 arch_2 ... arch_n

### Building For Windows <span id="win32-cross" />

windows builds are cross compiled from debian/ubuntu linux

additional build requirements:

* nsis
* cpack
* rsvg-convert (`librsvg2-bin` package on Debian/Ubuntu)

setup:

    $ sudo apt install build-essential cmake git pkg-config mingw-w64 nsis cpack automake libtool
    $ sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
    $ sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix

building:

    $ git clone --recursive https://github.com/session-foundation/session-router
    $ cd session-router
    $ ./contrib/windows.sh
    
### Compiling for MacOS <span id="mac-compile" />

Source code compilation of Session Router by end users is not supported or permitted by apple on their platforms, see [this](../contrib/macos/README.txt) for more information.

If you find this disagreeable consider using a platform that permits compiling from source.

### FreeBSD <span id="freebsd-install" />

Currently has no VPN Platform code, see issue `#1513`

build:

    $ pkg install cmake git pkgconf
    $ git clone --recursive https://github.com/session-foundation/session-router
    $ cd session-router
    $ mkdir build
    $ cd build
    $ cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DSTATIC_LINK=ON -DBUILD_STATIC_DEPS=ON ..
    $ make

install (root):

    # make install
    
### Android <span id="apk-install" />

We have an Android APK for Session Router VPN via android VPN API. 

Coming to F-Droid whenever that happens. [[issue]](https://github.com/session-foundation/session-router-flutter-app/issues/8)

* [source code](https://github.com/session-foundation/session-router-flutter-app)
