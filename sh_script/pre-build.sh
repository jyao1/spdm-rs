#!/bin/bash

TARGET_OPTION="x86_64-unknown-none"
process_args() {
    while getopts ":t:" option; do
        case "${option}" in
            t)
                TARGET_OPTION=${OPTARG}
            ;;
            *)
                echo "Invalid option '-$OPTARG'"
                exit 1
            ;;
        esac
    done
}

patch-ring() {
    # apply the patch set for ring
    pushd external/ring
    git reset --hard 2723abbca9e83347d82b056d5b239c6604f786df
    git clean -xdf
    case "$TARGET_OPTION" in
        "x86_64-unknown-none")
            git apply ../patches/ring/0001-Support-x86_64-unknown-none-target.patch
            git apply ../patches/ring/0002-Disable-checks-for-SSE-and-SSE2.patch
            git apply ../patches/ring/0003-introduce-EphemeralPrivateKey-serialization.patch
            git apply ../patches/ring/0004-Introduce-digest-de-serialization.patch
        ;;
        *)
            echo "Unsupported target for ring, builds may not work!"
        ;;
    esac
    popd
}

setup-aws-lc-rs() {
    # setup aws-lc-rs: init nested submodule and fix symlinks
    # Note: run git checkout first, then fix symlinks, then apply patches.
    # git checkout restores the builder symlink as a plain file on Windows/WSL.
    pushd external/aws-lc-rs
    git checkout -- .
    popd

    bash external/patches/aws-lc-rs/setup-aws-lc-rs.sh

    # apply the patch set for aws-lc-rs
    pushd external/aws-lc-rs
    git apply ../patches/aws-lc-rs/0001-Add-no_std-support-for-aws-lc-rs.patch
    popd

    # fix aws-lc-sys generated bindings for no_std (std:: -> core::)
    python3 external/patches/aws-lc-rs/fix_aws_lc_sys.py
}

format-patch() {
    patch-ring
    setup-aws-lc-rs
}

process_args "$@"
format-patch
