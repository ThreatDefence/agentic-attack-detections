# Roadmap

Attack frameworks change their names and strings easily. What an attacking AI agent does is harder to hide: it works at machine speed, tries many tools in minutes and leaves files behind. So more of the work here now goes into rules for that behavior, and into proving that every rule works.

There are no dates. This page is updated with each release.

## Now

- **Behavior rules.** Machine-speed activity in Azure, Entra and Microsoft 365. Many attack tools on one host within minutes. Agent work folders and reports left on disk.
- **Proof.** Test events for every Sigma rule, Zeek tests in CI, and a sample log for each hunt.

## Next

- **More log sources.** Google Cloud, Okta, Kubernetes and build pipelines.
- **Tripwires.** Bait that an agent takes and a person doesn't.
- **Easier setup.** One-step deployment for Microsoft Sentinel, Splunk and Elastic content for every framework. Issues: [Sentinel](https://github.com/ThreatDefence/agentic-attack-detections/issues/23), [Splunk](https://github.com/ThreatDefence/agentic-attack-detections/issues/24), [Elastic](https://github.com/ThreatDefence/agentic-attack-detections/issues/25).

## Later

- A safe kit that reproduces a framework's traces, so you can test your own pipeline.
- Notes for each behavior on what to check when a rule fires.

Want something added or moved up? Open an issue. A false positive report, a public sighting or sample events all help.
