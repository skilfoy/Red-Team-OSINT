# Red-Team-OSINT

The script performs extensive Open Source Intelligence (OSINT) on a given domain, utilizing a wide range of sources and tools to gather detailed information. The script covers various aspects of OSINT, including domain information, DNS records, social media profiles, internet-connected device details, breach data, email harvesting, and more.

### Key Functionalities

1. **WHOIS Information**
   - Fetches WHOIS data for the given domain using the `whois` package.

2. **DNS Records**
   - Retrieves DNS records using the HackerTarget API.

3. **Social Media Profiles**
   - Scrapes LinkedIn profiles related to the domain using Google search.
   - Searches for Twitter profiles related to the domain using the Twitter API.

4. **Shodan Information**
   - Uses the Shodan API to find details about internet-connected devices associated with the domain.

5. **Reverse IP Lookup**
   - Performs reverse IP lookup to find other domains hosted on the same server using the HackerTarget API.

6. **Breached Data**
   - Checks for data breaches related to the domain using the Have I Been Pwned API.

7. **Email Harvesting**
   - Uses the Hunter.io API to find email addresses associated with the domain.

8. **Pastebin Mentions**
   - Scrapes Google search results to find mentions of the domain on Pastebin.

9. **SecurityTrails Information**
   - Fetches detailed domain information using the SecurityTrails API.

10. **PublicWWW Results**
    - Searches for websites using the same analytics or advertising code as the domain using PublicWWW.

11. **CertSpotter Information**
    - Retrieves SSL certificate details for the domain using the CertSpotter API.

12. **GitHub Repositories**
    - Finds public repositories or code snippets mentioning the domain using the GitHub Search API.

13. **Wayback Machine Snapshots**
    - Gets historical snapshots of the website using the Wayback Machine API.

14. **ZoomEye Information**
    - Fetches information on the domain, useful for bypassing WAFs, using the ZoomEye API.

15. **Criminal-IP Information**
    - Provides domain intelligence and reputation information using the Criminal-IP API.

16. **Censys Information**
    - Searches for IPv4 records related to the domain using the Censys API.

17. **crt.sh Information**
    - Fetches SSL certificate information from crt.sh.

18. **AbuseIPDB Information**
    - Checks if IPs are reported for abuse using the AbuseIPDB API.

19. **IP Validation**
    - Validates if the IP is available by performing a DNS lookup.

### Workflow

1. **Initialization**:
   - The script initializes various API clients using the provided API keys.

2. **Domain Information Gathering**:
   - The script collects WHOIS data, DNS records, and social media profiles related to the domain.

3. **Infrastructure and Device Information**:
   - Shodan and ZoomEye APIs are used to gather information on internet-connected devices.
   - Reverse IP lookup is performed to identify other domains hosted on the same server.

4. **Security and Breach Data**:
   - Checks for data breaches using the Have I Been Pwned API.
   - Gathers email addresses using Hunter.io.
   - Searches for Pastebin mentions.

5. **Detailed Domain Analysis**:
   - SecurityTrails, PublicWWW, CertSpotter, and Criminal-IP APIs are used for detailed domain analysis.
   - Historical snapshots are fetched using the Wayback Machine API.

6. **Certificate and Repository Information**:
   - SSL certificates are retrieved using crt.sh and CertSpotter.
   - GitHub is searched for repositories mentioning the domain.

7. **Validation and Abuse Checking**:
   - IP addresses are validated for availability.
   - AbuseIPDB is used to check if any IPs are reported for abuse.

8. **Compilation of OSINT Report**:
   - All gathered data is compiled into a comprehensive OSINT report and saved to a JSON file.

### Requirements

1. **API Keys**:
   - Users need to obtain API keys for the various services used in the script, including Shodan, Twitter, Hunter.io, SecurityTrails, CertSpotter, ZoomEye, Criminal-IP, Censys, and AbuseIPDB.

2. **Python Packages**:
   - Required Python packages include `requests`, `beautifulsoup4`, `python-whois`, `shodan`, `twython`, and `dnspython`.

### Required Packages

```bash
pip install requests beautifulsoup4 python-whois shodan twython dnspython
```
### Example Script Execution

To run the script, the user needs to execute it and provide the target domain when prompted:
```bash
python osint_script.py
```
The user will be prompted to enter the target domain, and the script will then perform the OSINT activities, generating an OSINT report saved as a JSON file named `osint_report_<domain>.json`.

### Comprehensive OSINT Report

The final OSINT report is a JSON file that includes detailed information from all the sources and tools mentioned, providing a thorough overview of the target domain's online presence, security posture, and potential vulnerabilities.

This extensive OSINT script is a powerful tool for cybersecurity professionals conducting penetration testing, red teaming, or general reconnaissance on target domains. It leverages a wide range of public and semi-public information sources to build a comprehensive intelligence profile.
