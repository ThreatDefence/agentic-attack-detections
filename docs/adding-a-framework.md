# Adding a framework

Every framework follows the same shape, so the tools, CI and feeds pick it up without changes beyond one line in the feed builder.

## Layout

```text
frameworks/<name>/
  README.md                 what the framework is, what is in the folder, quick start
  source-code-signals.md    what its code leaves behind, with file references and how hard each signal is to remove
  coverage.md               behavior by platform
  hunting-order.md          where to start
  sentinel/hunting/*.kql    numbered KQL hunts, NN-short-name.kql
  sentinel/analytics/*.yaml Sentinel scheduled rule templates
  sigma/<category>/*.yml    Sigma rules
  suricata/<name>.rules     hand-written rules
  yara/<name>.yar           YARA rules
```

`frameworks/<name>/suricata/<name>-ip.rules` and `frameworks/<name>/zeek/intel/<name>.intel` are generated. Do not edit them by hand.

## Steps

1. Add the framework to `FRAMEWORKS` in `tools/build_feeds.py`: display name, aliases, a one-line description, the actor label used for the framework's own operators, and the next free Suricata address-rule SID base.
2. Add its indicators to `iocs/indicators.csv` with `framework` set to its folder name. An indicator shared with another framework keeps one row with both names, space separated.
3. Put rules that would work for any agentic framework in `behaviors/` rather than in the framework folder. Coding-agent abuse, tool bursts, proxy rotation and post-exploitation patterns usually belong there.
4. Give every rule its ATT&CK techniques in the format [CONTRIBUTING.md](../CONTRIBUTING.md) lists for its kind.
5. Run `python3 tools/build_feeds.py`, `python3 tools/convert.py`, `python3 tools/build_attack.py` and `python3 tools/validate.py`, and commit everything they regenerate. Add one case per Suricata rule, and a near miss, to `tests/suricata/run_tests.py`: the run fails if a rule has no case.
6. Add the framework to the tables in the root `README.md`.

## Number ranges

Suricata rule IDs (SIDs) come from the block 3800000 to 3819999, the range requested for this project at [sidallocation.org](https://sidallocation.org) so the rules don't collide with other rule sets. Each framework gets a block of 1,000.

| Framework | Suricata rules | Suricata address rules |
|---|---|---|
| ARTEX | 3800001 to 3800499 | from 3800500 |
| Cairn | 3801001 to 3801499 | from 3801500 |
| PentAGI | 3802001 to 3802499 | from 3802500 |
| HexStrike | 3803001 to 3803499 | from 3803500 |
| CyberStrikeAI | 3804001 to 3804499 | from 3804500 |
| Strix | 3805001 to 3805499 | from 3805500 |
| Hermes Agent | 3806001 to 3806499 | from 3806500 |
| Agent Zero | 3807001 to 3807499 | from 3807500 |
| RedAmon | 3808001 to 3808499 | from 3808500 |
| Xalgorix | 3809001 to 3809499 | from 3809500 |
| Pentest Swarm AI | 3810001 to 3810499 | from 3810500 |
| Next framework | 3811001 to 3811499 | from 3811500 |

Rules in `behaviors/suricata/` use numbers inside the Cairn block (3801010 to 3801059), where they were first published. Sigma and Sentinel rule ids are UUIDv5 values derived from the file path, so they stay stable as long as a file is not renamed.
