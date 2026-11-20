# REWS Verification Checklist

| ID | Test | Expected result |
|---|---|---|
| TC-01 | Open `/` | Overview screen loads and API connection reports connected |
| TC-02 | Click each sidebar item | A distinct application view replaces the previous view; page does not anchor-scroll |
| TC-03 | Enter a valid folder and start monitoring | Baseline count appears and state becomes Active |
| TC-04 | Enter an invalid folder | Clear validation error; monitor remains stopped |
| TC-05 | Create or modify a file in monitored folder | Event appears in the alert register after the next poll |
| TC-06 | Delete a monitored file | Medium file-deletion alert is recorded |
| TC-07 | Create a `.locked` file in monitored folder | High suspicious-extension alert is recorded |
| TC-08 | Generate more changes than threshold | Critical rapid-change alert is recorded |
| TC-09 | Run a folder scan | Inventory rows include size, modified time, SHA-256 and rule flags |
| TC-10 | Search inventory | Rows filter by filename/path |
| TC-11 | Acknowledge one alert | Status changes to Acknowledged |
| TC-12 | Acknowledge all | All open alerts become Acknowledged |
| TC-13 | Open scan history details | Stored file scan results load |
| TC-14 | Download JSON/CSV report | Browser downloads structured report files |
| TC-15 | Open print report | Print dialog opens with timestamped report |
| TC-16 | Save settings | Values persist in SQLite and update monitoring configuration |

## Safety notes
- Test with `data/demo_workspace`, not system directories or personal folders.
- The demo-change endpoint only creates harmless sample text files and is restricted to the bundled demo workspace.
- Detection rules are heuristic indicators and do not establish that a file or system is infected.
