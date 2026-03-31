#!/usr/bin/env python3
"""Patch aws-lc-sys for no_std support.

Modifies aws-lc-sys and aws-lc-rs to support #![no_std] builds:
1. aws-lc-sys/Cargo.toml: add 'std' feature (default)
2. aws-lc-sys/src/lib.rs: add #![no_std] and fix std imports
3. aws-lc-sys generated bindings: replace std:: with core:: paths
4. aws-lc-rs/Cargo.toml: wire std feature to aws-lc-sys
"""
import os
import glob

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
AWS_LC_SYS = os.path.join(BASE, "external", "aws-lc-rs", "aws-lc-sys")

# 1. aws-lc-sys/Cargo.toml: add std feature
cargo_path = os.path.join(AWS_LC_SYS, "Cargo.toml")
with open(cargo_path, "r") as f:
    content = f.read()
if "std = []" not in content:
    content = content.replace(
        "default = ['all-bindings']",
        "std = []\ndefault = ['all-bindings', 'std']"
    )
    with open(cargo_path, "w") as f:
        f.write(content)
    print("Patched aws-lc-sys/Cargo.toml")
else:
    print("aws-lc-sys/Cargo.toml already patched")

# 2. aws-lc-sys/src/lib.rs: add no_std attr and fix imports
lib_path = os.path.join(AWS_LC_SYS, "src", "lib.rs")
with open(lib_path, "r") as f:
    content = f.read()

if "no_std" not in content:
    # Add no_std attr after existing attrs
    old_header = '#![cfg_attr(not(clippy), allow(unexpected_cfgs))]\n#![cfg_attr(not(clippy), allow(unknown_lints))]'
    new_header = old_header + '\n#![cfg_attr(not(feature = "std"), no_std)]'
    content = content.replace(old_header, new_header)

    # Fix the use std::os::raw import
    content = content.replace(
        'use std::os::raw::{c_char, c_long, c_void};',
        'use core::ffi::{c_char, c_long, c_void};'
    )

    with open(lib_path, "w") as f:
        f.write(content)
    print("Patched aws-lc-sys/src/lib.rs")
else:
    print("aws-lc-sys/src/lib.rs already patched")

# 3. Fix generated bindings: replace std:: paths with core:: equivalents
# The generated bindings use both ::std:: and std:: paths.
# Replace them all with core:: equivalents.
bindings_dir = os.path.join(AWS_LC_SYS, "src")
binding_files = glob.glob(os.path.join(bindings_dir, "*_crypto.rs"))
patched_count = 0

for binding_file in binding_files:
    with open(binding_file, "r") as f:
        content = f.read()

    if "::std::" not in content and "std::os::raw" not in content:
        continue

    # Replace absolute paths (::std::X -> ::core::X)
    content = content.replace("::std::mem::", "::core::mem::")
    content = content.replace("::std::ptr::", "::core::ptr::")
    content = content.replace("::std::option::", "::core::option::")

    # Replace std::os::raw::c_TYPE with core::ffi::c_TYPE
    content = content.replace("::std::os::raw::", "::core::ffi::")
    content = content.replace("std::os::raw::", "core::ffi::")

    # Replace remaining std:: paths
    content = content.replace("std::mem::", "core::mem::")
    content = content.replace("std::ptr::", "core::ptr::")
    content = content.replace("std::option::", "core::option::")

    # Handle spaced bindgen output: :: std :: mem :: etc.
    content = content.replace(":: std :: mem ::", ":: core :: mem ::")
    content = content.replace(":: std :: ptr ::", ":: core :: ptr ::")
    content = content.replace(":: std :: option ::", ":: core :: option ::")
    content = content.replace(":: std :: os :: raw ::", ":: core :: ffi ::")

    with open(binding_file, "w") as f:
        f.write(content)
    patched_count += 1

print(f"Patched {patched_count} generated binding files")

# 4. aws-lc-rs/Cargo.toml: wire std feature to aws-lc-sys
aws_lc_rs_cargo = os.path.join(BASE, "external", "aws-lc-rs", "aws-lc-rs", "Cargo.toml")

with open(aws_lc_rs_cargo, "r") as f:
    content = f.read()
if 'std = ["aws-lc-sys/std"]' not in content:
    content = content.replace(
        'std = []',
        'std = ["aws-lc-sys/std"]'
    )
    with open(aws_lc_rs_cargo, "w") as f:
        f.write(content)
    print("Patched aws-lc-rs/Cargo.toml")
else:
    print("aws-lc-rs/Cargo.toml already patched")

print("All patches applied successfully!")
