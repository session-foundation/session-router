#!/usr/bin/env bash

# Script used by CI to upload a static build to builds.session.codes.  UPLOAD_OS names the platform
# (e.g. linux-amd64) and SSH_KEY holds the upload key.

set -o errexit

if [ -z "$UPLOAD_OS" ] || [ -z "$SSH_KEY" ]; then
    echo -e "\n\n\n\e[31;1mUnable to upload: UPLOAD_OS and SSH_KEY must both be set\e[0m"
    exit 1
fi

echo "$SSH_KEY" >ssh_key

set -o xtrace  # Don't start tracing until *after* we write the ssh key

chmod 600 ssh_key

if [ -n "$CI_COMMIT_TAG" ]; then
    # For a tag build use something like `session-router-linux-amd64-v1.2.3`
    base="session-router-$UPLOAD_OS-$CI_COMMIT_TAG"
else
    # Otherwise build a length name from the datetime and commit hash, such as:
    # session-router-linux-amd64-20200522T212342Z-04d7dcc54
    base="session-router-$UPLOAD_OS-$(date --date=@$CI_PIPELINE_CREATED +%Y%m%dT%H%M%SZ)-${CI_COMMIT_SHA:0:9}"
fi

mkdir -v "$base"
# TODO FIXME: bundle s-r-cntrl once it does something more useful
cp -av build/session-router{,-config} "$base"
archive="$base.tar.xz"
tar cJvf "$archive" "$base"

upload_to="builds.session.codes/${CI_REPO// /_}/${CI_COMMIT_BRANCH// /_}"

# sftp doesn't have any equivalent to mkdir -p, so we have to split the above up into a chain of
# -mkdir a/, -mkdir a/b/, -mkdir a/b/c/, ... commands.  The leading `-` allows the command to fail
# without error.
upload_dirs=(${upload_to//\// })
mkdirs=
dir_tmp=""
for p in "${upload_dirs[@]}"; do
    dir_tmp="$dir_tmp$p/"
    mkdirs="$mkdirs
-mkdir $dir_tmp"
done
sftp -i ssh_key -b - -o StrictHostKeyChecking=off drone@builds.session.codes <<SFTP
$mkdirs
put $archive $upload_to
SFTP

set +o xtrace

echo -e "\n\n\n\n\e[32;1mUploaded to https://${upload_to}/${archive}\e[0m\n\n\n"
