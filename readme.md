# letsploit

letsploit is a tool that detects the patch level of the local or another windows 10 system, checks it against the latest available patches and finds potential cve vulnerabilities as well as publicly available exploit code.

Inspired by following projects
1) bitsadmin's WESNG [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)
2) rasta-mouse's WATSON [https://github.com/rasta-mouse/Watson](https://github.com/rasta-mouse/Watson)
3) rasta-mouse's SHERLOCK [https://github.com/rasta-mouse/Sherlock](https://github.com/rasta-mouse/Sherlock)

Expect to find dirty code and some bug, this is some of first version ;)

## Installation

Some pip packages required. Look at letsploit imports.
Tested with python 3.x


## Usage

```
Usage:
letsploit.py -builds           :Output all available builds/revisions
letsploit.py -patchlevel <rev> :Output patchlevel and missing patches only
letsploit.py -vulns <rev>      :Output all unpatched CVEs
letsploit.py -pocs <rev>       :Output all unpatched CVEs with public POCs on Github

Use <rev> to query informations about another system. If nothing is specified the local system is evaluated.
Example: <rev>=19041.572 > W10 2004 Patchlevel October 2020

letsploit.py -updateCves       :Update KB/CVE Table via MSRC API
letsploit.py -updatePocs       :Update POC Table via GIT
letsploit.py -updateBuilds     :Update BUILDS via MS Update History Website

Windows 10 Client OS 1503-20H2 supported.
```

## Contact

@atn1ght1 Twitter

## License
[MIT](https://choosealicense.com/licenses/mit/)
