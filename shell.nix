# SPDX-FileCopyrightText: 2026 Niklas Wildenburg
# SPDX-License-Identifier: AGPL-3.0-or-later

{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = [
    pkgs.spamassassin
    pkgs.swaks
    (pkgs.python3.withPackages (ps: with ps; [ pyspf dkimpy checkdmarc dnspython ]))
  ];
  shellHook = ''
    echo "mailcheck: ./check.sh [file.eml ...]  (default: *.eml)"
  '';
}
