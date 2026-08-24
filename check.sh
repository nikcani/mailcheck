#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Niklas Wildenburg
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# mailcheck — offline SPF/DKIM/DMARC analysis of raw .eml files
# Copyright (C) 2026 Niklas Wildenburg
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -u
files=("$@")
[ $# -eq 0 ] && files=(*.eml)

for f in "${files[@]}"; do
        [ -f "$f" ] || continue
        printf '\n===== %s =====\n' "$f"
        hdr=$(sed '/^$/q' "$f")

        # sender IP: trust receiver's Authentication-Results, else last public bracketed IP
        ip=$(printf '%s\n' "$hdr" | grep -oiE 'sender IP is [0-9.]+' | grep -oE '[0-9.]+' | head -1)
        if [ -z "$ip" ]; then
                ip=$(printf '%s\n' "$hdr" | grep -oE '[][()][0-9]{1,3}(\.[0-9]{1,3}){3}[])]' | tr -d '[]()' |
                        grep -vE '^(10|127|0)\.|^169\.254\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.' | tail -1)
        fi
        esc=$(printf '%s' "$ip" | sed 's/\./\\./g')
        helo=$(printf '%s\n' "$hdr" | grep -iE "Received: from .*[][(]?${esc}[])]?" |
                sed -E 's/.*[Ff]rom ([^ ]+).*/\1/' | head -1)
        env=$(printf '%s\n' "$hdr" | grep -m1 -i '^Return-Path:' | grep -oE '[^<>[:space:]]+@[^<>[:space:]]+')
        hf=$(printf '%s\n' "$hdr" | grep -m1 -i '^From:' | grep -oE '[^<>[:space:]]+@[^<>[:space:]]+')
        [ -z "$env" ] && env="$hf"
        printf 'ip=%s helo=%s envfrom=%s hdrfrom=%s\n' "${ip:-?}" "${helo:-?}" "$env" "$hf"

        printf '%s\n' "$hdr" | grep -i -A3 '^Authentication-Results:' | head -8

        if printf '%s\n' "$hdr" | grep -qi '^DKIM-Signature:'; then
                printf '%s\n' "$hdr" | grep -oiE '[[:space:]](d|s)=[^;]+' | tr -s ' ' | head -4
                dkimverify <"$f" >/dev/null 2>&1 && echo "DKIM: PASS" || echo "DKIM: FAIL (bad sig)"
        else
                echo "DKIM: none (unsigned)"
        fi

        [ -n "$ip" ] && python3 -W ignore::DeprecationWarning -m spf "$ip" "$env" "${helo:-$ip}" 2>/dev/null | head -3

        checkdmarc "${hf##*@}" 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("SPF:  ", d.get("spf",{}).get("record"))
print("DMARC:", d.get("dmarc",{}).get("record"))
m=d.get("mx",{}).get("hosts",[])
print("MX:   ", ", ".join(h.get("hostname","")+" "+str(h.get("addresses",[])) for h in m))' 2>/dev/null

        spamassassin -t <"$f" 2>/dev/null | grep -E '^X-Spam-Status|^ ?-?[0-9.]+ [A-Z_]{3,}' | head -15
done
