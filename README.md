# COMP2152 — Term Project: CTF Bug Bounty

## Team Name
<!-- Replace with your team name -->
Team: BountyHunters-2152

## Team Members

| Member               | Vulnerability Found                     | Branch Name               |
|----------            |-----------------------------------      |---------------------------|
| Kalid Ali            | SQL Injection (search.0x10.cloud)       | kalid_search_sqli         |
| Mohamed Amine OUATAR | Unrestricted Upload (upload.0x10.cloud) | amine_unrestricted_upload |
| Joshua Zaakir | Publicly Accessible Admin Panel | josh_project_part |
| _______              | _______                                 | _______                   |

## Videos

Each team member records a short video (max 3 minutes) explaining their vulnerability. Add your YouTube links below:

- Kalid Ali: https://www.youtube.com/watch?v=5aqu3l44CoE
- Mohamed Amine OUATAR: https://www.youtube.com/watch?v=kZ-0Ig5jMvc
- Joshua Zaakir: pending

## Target

- Server: `0x10.cloud` and its subdomains
- Submission: http://submit.0x10.cloud
- Leaderboard: http://ranking.0x10.cloud

## Important: Rate Limit

The server allows **10 requests per second** per IP address. If you send requests too fast, you will get blocked (HTTP 429). Add a small delay between requests:

```python
import time
time.sleep(0.15)  # wait 150ms between requests
```

## Getting Started

1. Look at the three example scripts:
   - `example_http_check.py` — checks if a site uses HTTPS (uses `urllib`)
   - `example_port_check.py` — checks if a port is open (uses `socket`)
   - `example_header_check.py` — reads HTTP response headers for info leaks (uses `urllib`)
2. Run all examples: `python3 main.py`
3. Create your own branch: `git checkout -b your_vuln_name`
4. Write a Python script that finds and demonstrates a vulnerability
5. Submit your finding at http://submit.0x10.cloud
6. Merge your branch into master when done

## Rules

- **Python standard library only** — `socket`, `urllib`, `ssl`, `json`, `base64`, `time`. No pip packages.
- **Only scan `*.0x10.cloud`** — do not scan any other domain.
- **Respect the rate limit** — 10 requests/second max.
