# Elastic Security rules

Every rule in the repository as one Kibana Security import, plus an indicator match rule and the indicators it reads. Built by `tools/build_elastic.py` into [`generated/elastic_ndjson/`](../../generated/elastic_ndjson); do not edit by hand.

| Release file | What it is |
| --- | --- |
| [`agentic-attack-detections-elastic.ndjson`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-elastic.ndjson) | Every rule, one per line, all disabled |
| [`agentic-attack-detections-elastic-indicators-index.json`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-elastic-indicators-index.json) | The mapping for the `aad-indicators` index |
| [`agentic-attack-detections-elastic-indicators.ndjson`](https://github.com/ThreatDefence/agentic-attack-detections/releases/latest/download/agentic-attack-detections-elastic-indicators.ndjson) | The indicators, as a `_bulk` request into `aad-indicators` |

## Import the rules

In Kibana, **Security > Rules > Detection rules > Import rules**, choose `agentic-attack-detections-elastic.ndjson` and tick **Overwrite existing detection rules with conflicting "rule_id"**. Or with the API:

```bash
curl -u elastic -H 'kbn-xsrf: true' -F file=@agentic-attack-detections-elastic.ndjson \
  "https://<kibana>/api/detection_engine/rules/_import?overwrite=true"
```

Importing a newer release over an older one updates the rules in place, because each keeps its `rule_id`.

## Load the indicators

The indicator match rule reads the `aad-indicators` index. Create it and load the indicators:

```bash
curl -u elastic -X DELETE "https://<elasticsearch>/aad-indicators"     # on a reload: drops indicators no longer listed
curl -u elastic -X PUT "https://<elasticsearch>/aad-indicators" -H 'Content-Type: application/json' \
  --data-binary @agentic-attack-detections-elastic-indicators-index.json
curl -u elastic -X POST "https://<elasticsearch>/_bulk?refresh=true" -H 'Content-Type: application/x-ndjson' \
  --data-binary @agentic-attack-detections-elastic-indicators.ndjson
```

These are the indicators the plain lists in [`feeds/`](../../feeds) carry: medium and high confidence, with addresses past their review date left out. The rule matches source and destination addresses, DNS question names, URL and destination domains, full URLs, SHA-256 and MD5 file hashes and user agents. Reload the index with each release.

## Set up

1. The rules read `logs-*`, `filebeat-*`, `winlogbeat-*` and `packetbeat-*`. If your data is elsewhere, select the rules and use **Bulk actions > Index patterns**, or change `INDEX` in `tools/build_elastic.py` and rebuild.
2. Every rule is imported disabled. Run its query in Discover over 30 days to baseline it, then enable it.
3. Each rule's investigation guide links to the file it was built from.

## What is in the import

- Every Sigma rule as a query rule, converted to Lucene on ECS field names by the same pipeline as [`generated/elastic_lucene/`](../../generated/elastic_lucene), with its level as severity and risk score, and its ATT&CK tags as tactics, techniques and sub-techniques (ATT&CK 20.1).
- The Sigma correlation rules as threshold rules: the base rule's query, grouped by the correlation's fields, over its time span. A value count becomes a threshold with a cardinality.
- The base rules of those correlations as query rules of their own, at their own level (low or informational for most).
- The hand-written ARTEX rules in [`frameworks/artex/elastic/rules/`](../../frameworks/artex/elastic/rules) as they are.
- The indicator match rule.

## Limits

- The cloud rules (AWS CloudTrail, Entra ID, Azure activity, Okta) keep the field names of the provider's JSON, for example `eventName`, `userIdentity.arn` and `ResultType`. Elastic's AWS, Azure and Okta integrations rename those fields (`event.action`, `aws.cloudtrail.user_identity.arn`, `azure.signinlogs.properties.status.error_code`), so these rules match only data that keeps the original names until the conversion maps them.
- Domains match as written: the indicators are lower case, so an event with an upper-case DNS name does not match the indicator rule.
- An address range in `iocs/indicators.csv` is left out of the indicator index, because an `ip` field holds one address. Suricata and the WAF rules cover ranges.

`tests/elastic/run_tests.py` imports the file into a real Kibana, enables every rule, checks that each runs, that the Sigma rules alert on their test events and that the indicator rule alerts on an event naming an indicator. `lab/lab.sh up elastic && lab/lab.sh test elastic` runs it locally; CI runs it on every pull request.
