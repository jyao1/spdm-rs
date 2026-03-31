#!/bin/bash
# Setup script for aws-lc-rs submodule on Windows and Linux.
#
# aws-lc-rs has a nested submodule (aws-lc-sys/aws-lc) and uses symlinks
# (aws-lc-sys/builder -> ../builder). On Windows, git symlinks may not
# resolve properly, so we replace them with copies or junctions.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AWS_LC_RS_DIR="$(cd "$SCRIPT_DIR/../../aws-lc-rs" && pwd)"

echo "Setting up aws-lc-rs at: $AWS_LC_RS_DIR"

# Step 1: Initialize the nested aws-lc submodule
pushd "$AWS_LC_RS_DIR" > /dev/null
if [ ! -f "aws-lc-sys/aws-lc/CMakeLists.txt" ]; then
    echo "Initializing aws-lc-sys/aws-lc submodule..."
    git submodule update --init --depth 1 aws-lc-sys/aws-lc
fi
# Shallow clone may miss some directories. Ensure s2n-bignum headers exist.
if [ ! -f "aws-lc-sys/aws-lc/third_party/s2n-bignum/s2n-bignum-imported/include/_internal_s2n_bignum.h" ]; then
    echo "Restoring s2n-bignum include directory..."
    pushd aws-lc-sys/aws-lc > /dev/null
    git checkout HEAD -- third_party/s2n-bignum/s2n-bignum-imported/include/
    popd > /dev/null
fi
popd > /dev/null

# Step 2: Fix symlinks on Windows
# aws-lc-sys/builder is a symlink to ../builder which may not resolve on Windows
BUILDER_LINK="$AWS_LC_RS_DIR/aws-lc-sys/builder"
BUILDER_TARGET="$AWS_LC_RS_DIR/builder"

# The builder entry may be a regular file (git stores symlink targets as plain files
# when core.symlinks is false, or after git checkout on Windows/WSL-on-NTFS), a broken
# symlink, or missing entirely. In all cases we need a working link/junction to ../builder.
if [ ! -d "$BUILDER_LINK" ]; then
    echo "Fixing aws-lc-sys/builder symlink..."
    rm -f "$BUILDER_LINK"
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
        # On Windows (Git Bash / MSYS2), use directory junction via cmd
        cmd //c "mklink /J \"$(cygpath -w "$BUILDER_LINK")\" \"$(cygpath -w "$BUILDER_TARGET")\""
    else
        # On Linux/macOS/WSL, recreate as proper symlink
        ln -s ../builder "$BUILDER_LINK"
    fi
fi

echo "aws-lc-rs setup complete."
