# Linux builds, in our Debian/Ubuntu images on the docker agents.

registry = "registry.session.codes/"

events = ["push", "pull_request", "tag", "manual"]

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

default_deps = [
    "g++",
    "libcli11-dev",
    "libcurl4-openssl-dev",
    "libevent-dev",
    "libfmt-dev",
    "libgnutls28-dev",
    "libsodium-dev",
    "libspdlog-dev",
    "libsqlite3-dev",
    "libssl-dev",
    "libsystemd-dev",
    "libunbound-dev",
    "libzmq3-dev",
    "libzstd-dev",
    "make",
    "nettle-dev",
    "nlohmann-json3-dev",
    "python3-dev",
]

# Static builds build their dependencies themselves.
static_deps = ["automake", "g++", "libtool", "python3-dev"]

# Our own libraries, from deb.session.foundation.
session_repo_deps = ["liboxen-logging-dev", "liboxenmq-dev", "liboxenc-dev", "liboxen-quic-dev"]

default_cmake = {
    "WITH_SETCAP": False,
    "CMAKE_CXX_FLAGS": "-fdiagnostics-color=always",
    "CMAKE_BUILD_TYPE": "Release",
    # Ours and oxen-logging's, both on by default.
    "WITH_LTO": False,
    "USE_LTO": False,
    "LOCAL_MIRROR": "https://builds.session.codes/deps",
}

# The build marks a tagged commit as a release, which needs the tags fetched.
clone = [{"name": "clone", "image": "woodpeckerci/plugin-git:2", "settings": {"tags": True}}]

def cmake_args(opts):
    args = []
    for k, v in opts.items():
        if type(v) == "bool":
            v = "ON" if v else "OFF"
        elif " " in v:
            v = '"%s"' % v
        args.append("-D%s=%s" % (k, v))
    return " ".join(args)

def deps_with(add = [], remove = []):
    return sorted([d for d in default_deps if d not in remove] + add)

def workflow(name, arch, steps, skip_packaging_branches = True):
    when = {"event": events}
    if skip_packaging_branches:
        # The debian/* and ubuntu/* branches build packages, with CI configs of their own.
        when["branch"] = {"exclude": ["debian/*", "ubuntu/*"]}
    return {
        "name": name,
        "labels": {"platform": "linux/" + arch, "backend": "docker"},
        "when": [when],
        "clone": clone,
        "steps": steps,
    }

# A build given upload_os is a static release build: it checks what the binary links to, and uploads
# it to builds.session.codes from pushes to our own repositories.
def linux(
        name,
        image,
        arch = "amd64",
        deps = default_deps,
        session_repo = True,
        cmake = {},
        jobs = 6,
        upload_os = None):
    image = registry + image
    commands = [
        'echo "Building on $${CI_MACHINE}"',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        apt_get + " update",
        apt_get + " install -y eatmydata",
        "eatmydata " + apt_get + " dist-upgrade -y",
    ]
    if session_repo:
        commands += [
            "eatmydata " + apt_get + " install --no-install-recommends -y lsb-release",
            "cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d",
            "echo deb http://deb.session.foundation $$(lsb_release -sc) main >/etc/apt/sources.list.d/session.list",
            "eatmydata " + apt_get + " update",
            apt_get + " install -y " + " ".join(session_repo_deps),
        ]
    opts = dict(default_cmake)
    opts.update(cmake)
    commands += [
        "eatmydata " + apt_get + " install --no-install-recommends -y " +
        " ".join(["cmake", "git", "pkg-config", "ccache"] + deps),
        "mkdir build",
        "cd build",
        "cmake .. " + cmake_args(opts),
        "VERBOSE=1 make -j%d" % jobs,
        "cd ..",
    ]
    steps = [{"name": "build", "image": image, "pull": True, "commands": commands}]
    if upload_os:
        commands.append("./contrib/ci/check-static-libs.sh")
        steps.append({
            "name": "upload",
            "image": image,
            "environment": {"SSH_KEY": {"from_secret": "SSH_KEY"}, "UPLOAD_OS": upload_os},
            "commands": ["./contrib/ci/static-upload.sh"],
            "when": [{"event": ["push", "tag", "manual"], "repo": "session-foundation/*"}],
        })
    return workflow(name, arch, steps)

def clang(version):
    cmake = {
        "CMAKE_C_COMPILER": "clang-%d" % version,
        "CMAKE_CXX_COMPILER": "clang++-%d" % version,
        # clang's LTO objects need a linker that reads LLVM bitcode, which the default bfd linker
        # here doesn't, so the static dependencies have to be built without it.
        "SESSIONDEPS_LTO": False,
    }
    if version >= 21:
        # clang-21 breaks lots of things in fmt 10, so we have to avoid it.
        cmake.update(FORCE_OXENLOGGING_SUBMODULE = True, OXEN_LOGGING_FORCE_SUBMODULES = True)
    return linux(
        "Debian sid: clang-%d" % version,
        "debian-sid-clang",
        deps = deps_with(add = ["clang-%d" % version, "llvm-%d" % version], remove = ["g++"]),
        cmake = cmake,
    )

def full_llvm(version):
    cmake = {
        "CMAKE_C_COMPILER": "clang-%d" % version,
        "CMAKE_CXX_COMPILER": "clang++-%d" % version,
        "CMAKE_CXX_FLAGS": "-stdlib=libc++",
        # Any system C++ library is built against libstdc++ and so can't be linked here.  The image
        # has our apt repo configured, so newer releases of our libraries get installed regardless.
        "DEPS_FORCE_SUBMODULE": True,
        "FORCE_OXENLOGGING_SUBMODULE": True,
        "OXEN_LOGGING_FORCE_SUBMODULES": True,
    }
    for kind in ["EXE", "MODULE", "SHARED"]:
        cmake["CMAKE_%s_LINKER_FLAGS" % kind] = "-fuse-ld=lld-%d" % version
    return linux(
        "Debian sid: llvm-%d" % version,
        "debian-sid-clang",
        deps = deps_with(
            add = [
                "clang-%d" % version,
                "llvm-%d" % version,
                "lld-%d" % version,
                "libc++-%d-dev" % version,
                "libc++abi-%d-dev" % version,
                "libunwind-%d-dev" % version,
                "libngtcp2-crypto-gnutls-dev",
                "libngtcp2-dev",
            ],
            remove = ["g++"],
        ),
        session_repo = False,
        cmake = cmake,
    )

# Static builds, uploaded to builds.session.codes.  In general:
# - armhf and arm64 build on the oldest debian distro we support.  Technically there is some arm64
#   ubuntu support, but the arm linux ecosystem seems to be much more built on top of debian rather
#   than ubuntu.
# - amd64 we build on the oldest Debian *or* Ubuntu distro, so that it should work on that or
#   anything newer.
#
# They target the architecture as a whole, not the build machine's CPU: on x86 the build system then
# applies its own flags for public releases; elsewhere cflags must give the target.
def static_release(name, image, upload_os, cflags = None, cxxflags = None, arch = "amd64", jobs = 6, lto = False):
    cmake = {
        "BUILD_STATIC_DEPS": True,
        "SROUTER_NATIVE_BUILD": False,
        "WITH_SYSTEMD": False,
        "WITH_LTO": lto,
        "USE_LTO": lto,
    }
    if cflags:
        cmake["CMAKE_C_FLAGS"] = cflags
        cmake["CMAKE_CXX_FLAGS"] = cxxflags if cxxflags else cflags
    return linux(
        name,
        image,
        arch = arch,
        jobs = jobs,
        deps = static_deps,
        session_repo = False,
        cmake = cmake,
        upload_os = upload_os,
    )

def main(ctx):
    return [
        workflow("lint check", "amd64", [{
            "name": "build",
            "image": registry + "lint",
            "pull": True,
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " install --no-install-recommends -y git clang-format-19",
                "./contrib/ci/format-verify.sh",
            ],
        }], skip_packaging_branches = False),

        linux("Debian sid", "debian-sid"),
        linux("Debian sid: debug", "debian-sid", cmake = {"CMAKE_BUILD_TYPE": "Debug"}),
        linux("Debian sid: debug [arm64]", "debian-sid", arch = "arm64", jobs = 4, cmake = {"CMAKE_BUILD_TYPE": "Debug"}),

        clang(19),
        full_llvm(19),
        clang(21),
        full_llvm(21),

        linux("Debian testing", "debian-forky"),
        linux("Debian testing [i386]", "debian-forky/i386"),
        linux("Debian testing [arm64]", "debian-forky", arch = "arm64", jobs = 4),
        linux("Debian testing [armhf]", "debian-forky/arm32v7", arch = "arm64", jobs = 4),

        linux("Debian 13: trixie", "debian-trixie"),
        linux("Debian 13: trixie [arm64]", "debian-trixie", arch = "arm64", jobs = 4),

        linux("Debian 12: bookworm", "debian-bookworm"),
        linux(
            "Debian 12: bookworm static: debug",
            "debian-bookworm",
            deps = static_deps,
            session_repo = False,
            cmake = {"CMAKE_BUILD_TYPE": "Debug", "BUILD_STATIC_DEPS": True},
        ),

        static_release(
            "Static armhf (Debian 12: bookworm)",
            "debian-bookworm/arm32v7",
            "linux-armhf",
            "-march=armv7-a+fp",
            cxxflags = "-march=armv7-a+fp -Wno-psabi",
            arch = "arm64",
            jobs = 4,
        ),
        static_release(
            "Static arm64 (Debian 12: bookworm)",
            "debian-bookworm",
            "linux-arm64",
            "-march=armv8-a",
            arch = "arm64",
            jobs = 4,
        ),
        static_release(
            "Static AMD64 (Ubuntu jammy)",
            "ubuntu-jammy",
            "linux-amd64",
            lto = True,
        ),

        linux("Ubuntu latest", "ubuntu-rolling"),
        linux("Ubuntu 24.04", "ubuntu-noble"),
        linux("Ubuntu 22.04", "ubuntu-jammy"),
    ]
