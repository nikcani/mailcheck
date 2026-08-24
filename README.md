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
  reconstructed from headers and is only as trustworthy as the relay that wrote
  them.
- Outlook `.msg` is a reconstructed MAPI object, not the wire format. DKIM will
  usually fail on a `msgconvert` output. Use the raw source.
- Mail relayed through a forwarding gateway will fail SPF by design — the
  evaluator sees the relay's IP, not the origin's. DKIM is the relay-independent
  mechanism.

## Provenance

I specified what this tool should do — offline SPF/DKIM/DMARC checking of raw
`.eml` files with FLOSS CLI tools, as an alternative to rate-limited or paid web
services like mail-tester.com — and directed the design decisions throughout.
The implementation was written by Claude Opus 5 (Anthropic) over an iterative
session in which I ran each version, fed back the actual output, and we
corrected from there.

It solved a real problem for me: diagnosing why monitoring mail relayed through
a corporate gateway was failing DMARC, and verifying the DKIM fix afterwards.
The results matched what the receiving MTA independently reported.

That said: **use at your own risk.** This is a diagnostic aid, not an
authoritative mail authentication validator. The header parsing makes
assumptions that will not hold for every message, and a wrong verdict here is
entirely possible. Verify anything important against the receiving MTA's own
`Authentication-Results:` header.
