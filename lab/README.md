# Detection lab: Splunk, Elastic and Microsoft Sentinel

A lab to try the rules by hand in the products they ship for, with test events already loaded. Splunk and Elasticsearch with Kibana run in Docker on your machine; Microsoft Sentinel runs in your own Azure workspace.

## Splunk and Elastic

Needs Docker with Compose and about 8 GB of memory for the containers (Colima: `colima start --cpu 4 --memory 8`), and the Python packages in `tools/requirements.txt`.

```bash
pip install -r tools/requirements.txt
lab/lab.sh up            # or: lab/lab.sh up splunk, lab/lab.sh up elastic
lab/lab.sh test          # load test events and rules, check every detection
lab/lab.sh status        # URLs and credentials
lab/lab.sh down          # stop, keep the data; lab/lab.sh reset deletes it
```

`up` writes `lab/.env` with new passwords and a HEC token on its first run (it is not committed), packages the Splunk app from this checkout and starts:

| | URL | Sign in | What is loaded |
| --- | --- | --- | --- |
| Splunk 10.6.2 | http://localhost:8000 | `admin` and `SPLUNK_PASSWORD` | the app from `deploy/splunk/`, the test-data app, events in `index=aad_test` |
| Kibana 9.5.5 | http://localhost:5601 | `elastic` and `ELASTIC_PASSWORD` | every rule under Security > Rules, events in `logs-aad.test-default`, alerts under Security > Alerts |

Starting Splunk accepts the Splunk General Terms and license (`SPLUNK_START_ARGS=--accept-license`), as the CI job does. Splunk publishes amd64 images only, so on Apple silicon it runs under emulation and its first start takes several minutes. Ports are bound to 127.0.0.1 only. Set `SPLUNK_IMAGE` or `ELASTIC_VERSION` in `lab/.env` to try other versions.

`test` runs the same checks against each product:

- **Splunk**: `tests/splunk/run_tests.py`, the CI test. It sends test events through HEC and checks every search.
- **Elastic**: `tests/elastic/run_tests.py`. It writes the same test events with ECS field names, runs every rule's Lucene query as the detection engine does and checks Elasticsearch agrees with the Sigma rule on each event, then imports every rule into Kibana in one NDJSON import, enables them, and checks each run succeeds and raises its alerts. The rules stay enabled, so Security > Alerts keeps showing them. `--ndjson file` imports your own file instead.

Both tests leave their events in place, so the searches, dashboard and alerts have something to show. Run `test` again to refresh them: the Elastic rules look back 9 minutes, so alerts appear only right after a run.

## Microsoft Sentinel

Sentinel cannot run locally. Use a lab workspace with Sentinel on and deploy the templates as `deploy/sentinel/README.md` describes. To test a fix to the templates, deploy the release first, then the template from your branch over it, and turn the rules on in the portal. `tests/kql/run_tests.py` covers the queries themselves in the Kusto emulator.
