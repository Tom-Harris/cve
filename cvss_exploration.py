from cvss import CVSS2, CVSS3, CVSS4
import json
import requests
import urllib3

# Proof of Concept Code - Not For Production
# Seriously, don't do this in prod..
urllib3.disable_warnings()

def localized_results(vector):
	r = CVSS3(vector)
	print('------------------------------------------------------')
	print('{0:30}  {1}'.format("Local Vector:", r.clean_vector()))
	print('{0:30}  {1}'.format("Local Base Score: ", r.scores()[0], "(", r.severities()[0], ")"))
	print('{0:30}  {1}'.format("Local Temporal Score: ", r.scores()[1], "(", r.severities()[1], ")"))
	print('{0:30}  {1}'.format("Local Environmental Score: ", r.scores()[2], "(", r.severities()[2], ")"))
	print('------------------------------------------------------')


## Set localization for Temporal and Environmental Attributes

## Fields: (X is undefined)
##      localized_t = 'E:X/RL:X/RC:X'
##      localized_environmental = 'CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X'
## https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

localized_temporal = "/E:H"
localized_environmental = "/MAV:L/CR:M/IR:M/AR:L"



## Collect CVEs

## Replace this section with a function that pulls the CVE's out of the Vulnerability
## scan.  For a large scan, be sure to pull out the system and application along with the CVE and CVSS
## vector (needed for recasting score based on actual exposure and impact) in a seperate list.  Populate
## the cve listing as shown.

## Future Work: Rebuild the list to be either a dictionary or a list of lists.

cves = []
with open("./InitialCVSS.txt", "r") as cve:
	for item in cve:
		cves.append(item.strip())
print(cves)

## Pull CVE info
for cve in cves:
	#base = 'https://cve.circl.lu/api/cve/'   # The output of this script is based on the RHEL API
	base = 'https://access.redhat.com/hydra/rest/securitydata/cve/'
	url = base + cve
	print('======================================================')
	resp = requests.get(url, verify=False)
	resp = (resp.content)
	resp = json.loads(resp)
	#print(url)                           ## This is to view the URL sent to the API 
	#print(json.dumps(resp, indent=2))    ## This is the entire JSON output
	print('{0:12}  {1}'.format("CVE:", resp['name']))
	print('------------------------------------------------------')
	if 'cvss3' in resp:
		print('{0:30}  {1}'.format("CVSS Base Score:", resp['cvss3']['cvss3_base_score']))
		print('{0:30}  {1}'.format("Vector:", resp['cvss3']['cvss3_scoring_vector']))
		localized_results(resp['cvss3']['cvss3_scoring_vector']+localized_temporal+localized_environmental)
	else:
		print('{0:12}  {1}'.format("CVSS Base Score:", "None Provided"))
		print('{0:12}  {1}'.format("Vector:", "None Provided"))
	print('{0:12}  {1}'.format("Desc:", resp['bugzilla']['description']))
	print('{0:12}  {1}'.format("Details:", resp['details']))
	if 'cwe' in resp:
		print('{0:12}  {1}'.format("CWE:", resp['cwe']))
	else:
		print('{0:12}  {1}'.format("CWE:", "None Provided"))
	if 'mitigation' in resp:
		print("Mitigations:\t", resp['mitigation']['value'])
	else:
		print('{0:12}  {1}'.format("Mitigations:", "None Provided"))
	print()
	print()
	print()

## Future Work: Output this to a JSON file for future work (comparison, import into VM database, Excel, etc.

## Future Work: Pull CWE information from scan results or from the CVE responses and build a module to 
## pull the CWE data directly from Mitre for detection, mitigation, and other interesting tidbits.
