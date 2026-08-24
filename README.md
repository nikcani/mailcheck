# mailcheck

Offline SPF / DKIM / DMARC analysis of raw `.eml` files, using FLOSS CLI tools
instead of rate-limited web services.

## Usage

    cd mailcheck        # direnv builds the nix shell
    ./check.sh          # all *.eml in cwd
    ./check.sh mail.eml # single file

Without direnv:

    nix-shell --run ./check.sh

## What it does

For each message it reconstructs the `(client IP, HELO, MAIL FROM)` triple from
the `Received:` and `Return-Path:` headers, then:

- prints the receiving MTA's own `Authentication-Results:` verdict
- verifies the DKIM signature locally (`dkimverify`) and shows `d=` / `s=`
- evaluates SPF against the reconstructed triple (`pyspf`)
- fetches the domain's SPF / DMARC / MX records (`checkdmarc`)
- scores the message with SpamAssassin

## Caveats

- SPF and DMARC cannot be fully verified from a file alone; the connecting IP is
  reconstructed from headers and is only as trustworthy as the relay that wrote them.
- Outlook `.msg` is a reconstructed MAPI object, not the wire format. DKIM will
  usually fail on a `msgconvert` output. Use the raw source.
- Mail relayed through a forwarding gateway will fail SPF by design — the
  evaluator sees the relay's IP, not the origin's. DKIM is the relay-independent
  mechanism.
