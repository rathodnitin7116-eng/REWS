import app, time, json
from pathlib import Path

client = app.app.test_client()

print('=== RUNNING FULL VERIFICATION SUITE ===')

# Ensure clean default settings before running tests
client.post('/api/settings', json={'burst_threshold': 8, 'poll_interval': 3, 'max_scan_files': 5000})

# TC-01: Open /
r01 = client.get('/')
assert r01.status_code == 200 and b'REWS | Security Operations' in r01.data
print('TC-01 PASSED: Root page renders successfully')

# TC-04: Invalid folder validation
r04 = client.post('/api/monitor/start', json={'path': 'C:/non_existent_folder_xyz_123'})
assert r04.status_code == 400 and 'does not exist' in r04.get_json()['error']
print('TC-04 PASSED: Invalid folder correctly rejected with 400')

# Setup clean demo workspace
r_demo = client.post('/api/demo-lab')
assert r_demo.status_code == 200
demo_path = r_demo.get_json()['path']
print('Demo workspace initialized at:', demo_path)

# TC-03: Start monitoring valid folder
r03 = client.post('/api/monitor/start', json={'path': demo_path})
assert r03.status_code == 200 and r03.get_json()['ok'] == True
baseline_count = r03.get_json()['baseline_files']
print(f'TC-03 PASSED: Monitoring started on {demo_path} with {baseline_count} baseline files')

# TC-05: Modify a file
test_file = Path(demo_path) / 'demo_note.txt'
test_file.write_text('Updated text for TC-05 at ' + str(time.time()), encoding='utf-8')
time.sleep(3.5)
alerts = client.get('/api/alerts').get_json()
tc05_match = [a for a in alerts if a['title'] == 'File modified during monitoring']
assert len(tc05_match) > 0, 'TC-05 failed to record modified alert'
print('TC-05 PASSED: File modified alert recorded')

# TC-07: Create .locked file
locked_file = Path(demo_path) / 'confidential.docx.locked'
locked_file.write_text('encrypted content simulation', encoding='utf-8')
time.sleep(3.5)
alerts = client.get('/api/alerts').get_json()
tc07_match = [a for a in alerts if a['title'] == 'Suspicious extension observed' and 'confidential.docx.locked' in a['file_path']]
assert len(tc07_match) > 0, 'TC-07 failed to record suspicious extension alert'
print('TC-07 PASSED: Suspicious extension alert recorded')

# TC-06: Delete a file
locked_file.unlink()
time.sleep(3.5)
alerts = client.get('/api/alerts').get_json()
tc06_match = [a for a in alerts if a['title'] == 'File deleted during monitoring']
assert len(tc06_match) > 0, 'TC-06 failed to record deleted alert'
print('TC-06 PASSED: File deleted alert recorded')

# TC-08: Burst changes exceeding threshold
r08 = client.post('/api/demo-change')
assert r08.status_code == 200
time.sleep(3.5)
alerts = client.get('/api/alerts').get_json()
tc08_match = [a for a in alerts if a['title'] == 'Rapid file-change burst detected']
assert len(tc08_match) > 0, 'TC-08 failed to record burst alert'
print('TC-08 PASSED: Rapid file-change burst alert recorded')

# Check events persistence
events = client.get('/api/monitor/events').get_json()
assert len(events) > 0, 'Events feed should not be empty'
print(f'Events feed verified: {len(events)} events preserved in live feed')

# TC-09 & TC-10: Folder scan
r09 = client.post('/api/scan', json={'path': demo_path})
assert r09.status_code == 200
scan_res = r09.get_json()
files_scanned = scan_res['files_scanned']
flagged_count = scan_res['flagged_count']
assert files_scanned > 0 and len(scan_res['files']) > 0
first_file = scan_res['files'][0]
assert 'sha256' in first_file and 'flags' in first_file and 'size' in first_file and 'modified' in first_file
print(f'TC-09 PASSED: Scan completed. Files: {files_scanned}, Flagged: {flagged_count}')

# TC-11 & TC-12: Acknowledge alerts
open_alerts = [a for a in client.get('/api/alerts').get_json() if a['status'] == 'Open']
assert len(open_alerts) > 0
aid = open_alerts[0]['id']
r11 = client.post(f'/api/alerts/{aid}/ack')
assert r11.status_code == 200
r12 = client.post('/api/alerts/ack-all')
assert r12.status_code == 200
remaining_open = [a for a in client.get('/api/alerts').get_json() if a['status'] == 'Open']
assert len(remaining_open) == 0
print('TC-11 & TC-12 PASSED: Single and bulk alert acknowledgments successful')

# TC-13: Scan history
scans = client.get('/api/scans').get_json()
assert len(scans) > 0
sid = scans[0]['id']
r13 = client.get(f'/api/scans/{sid}')
assert r13.status_code == 200 and 'files' in r13.get_json()
print('TC-13 PASSED: Scan history and detail loaded')

# TC-14: Reports JSON & CSV
r_json = client.get('/api/report.json')
assert r_json.status_code == 200 and 'rews_security_report.json' in r_json.headers.get('Content-Disposition', '')
r_csv = client.get('/api/report.csv')
assert r_csv.status_code == 200 and 'rews_alert_register.csv' in r_csv.headers.get('Content-Disposition', '')
print('TC-14 PASSED: JSON and CSV reports exported with correct headers')

# TC-15: Printable report
r_print = client.get('/api/report/print')
assert r_print.status_code == 200 and b'REWS Security Report' in r_print.data
print('TC-15 PASSED: Printable report generated')

# TC-16: Settings persistence
r16 = client.post('/api/settings', json={'burst_threshold': 12, 'poll_interval': 5, 'max_scan_files': 2500})
assert r16.status_code == 200
s16 = client.get('/api/settings').get_json()
assert s16['burst_threshold'] == 12 and s16['poll_interval'] == 5 and s16['max_scan_files'] == 2500
print('TC-16 PASSED: Settings successfully persisted')

# Restore default settings
client.post('/api/settings', json={'burst_threshold': 8, 'poll_interval': 3, 'max_scan_files': 5000})

# Stop monitor
client.post('/api/monitor/stop')
print('=== ALL TEST CASES PASSED SUCCESSFULLY! ===')
