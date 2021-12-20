# lastpymile
# `LastPyMile`: Identify the differences between build artifacts of PyPI packages and the respective source code repository
The paper has been published in the proceeding of [ESEC/FSE 2021](https://dl.acm.org/doi/10.1145/3468264.3468592).

Figure below in an overview of the LastPyMile workflow and internal components:
<img src="https://www.researchgate.net/profile/Duc-Ly-Vu/publication/352546142/figure/fig2/AS:1036480688427008@1624127661875/LastPyMile-in-the-context-of-the-overall-security-review-pipeline_W640.jpg" width="800">

`LastPyMile` extends the current package scanning techniques for malware injections.
The tool analyzes a package from the [PyPI](https://pypi.org) repository by:
1. Identifying the discrepancy (files and lines) between the source code and the package's artifact 
2. Scanning the discrepancy using Yara rules ([MalwareCheck patterns](https://github.com/pypa/warehouse/blob/main/warehouse/malware/checks/setup_patterns/check.py)) and AST code analysis ([Bandit4mal patterns](https://github.com/lyvd/bandit4mal)). 

As such, `LastPyMile` aims to detect malicious packages in the package owner hijacking, typosquatting/combosquatting attacks (See [Ohm et al.](https://link.springer.com/chapter/10.1007/978-3-030-52683-2_2), [Vu et al.](https://ieeexplore.ieee.org/abstract/document/9229803)). In these attacks, malicious code is injected into a package's artifact, which does not exist in the source code repository. 

In comparison to [the existing scanning tools employed by PyPI](https://warehouse.readthedocs.io/development/malware-checks.html#malware-checks)
LastPyMile reduces the number of alerts produced by a malware checking tool to a number that a human can check. Also, it
removes all the alerts from benign packages, and therefore, allows a clear distinction between benign and malicious
packages.

## History
`LastPyMile` is originally developed by [SAP Security Research](https://www.sap.com/documents/2017/12/cc047065-e67c-0010-82c7-eda71af511fa.html)
and [Security Group at the University of Trento](https://securitylab.disi.unitn.it/doku.php?id=start).

The tool is best described in the following scientific papers, please cite these if you use the tool for your research work:
- [Duc-Ly Vu](https://scholar.google.com/citations?hl=en&user=sl1ofC0AAAAJ), [Ivan Pashchenko](https://scholar.google.com/citations?user=Zy55O-YAAAAJ&hl=en),
[Fabio Massacci](https://scholar.google.com/citations?user=gC_ZVPgAAAAJ&hl=en), [Henrik Plate](https://scholar.google.com/citations?user=Kaleo5YAAAAJ&hl=en), [Antonino Sabetta](https://scholar.google.com/citations?hl=en&user=BhcceV8AAAAJ), [**Towards Using Source Code Repositories to Identify Software Supply Chain Attacks**](https://dl.acm.org/doi/abs/10.1145/3372297.3420015), ACM CCS 2020.
- [Duc-Ly Vu](https://scholar.google.com/citations?hl=en&user=sl1ofC0AAAAJ), [Ivan Pashchenko](https://scholar.google.com/citations?user=Zy55O-YAAAAJ&hl=en),
[Fabio Massacci](https://scholar.google.com/citations?user=gC_ZVPgAAAAJ&hl=en), [Henrik Plate](https://scholar.google.com/citations?user=Kaleo5YAAAAJ&hl=en), [Antonino Sabetta](https://scholar.google.com/citations?hl=en&user=BhcceV8AAAAJ), [**LastPyMile: identifying the discrepancy between sources and packages**](), ESEC/FSE 2021.

## Features
 - Identify the Github URL of a PyPI package
 - Identify the differences between build artifacts of software packages and the respective source code repository
 - Scan the differences using Yara rules and [bandit4mal](https://github.com/lyvd/bandit4mal)
 - Process a repository and artifact in parallel

## Installation
*Requires python 3.9*

- Suggested: Install venv and create virtual environment
```bash
python -m venv .vevn
#activate venv in window
.venv/Scripts/activate.bat
#activate venv in linux
source .venv/bin/activate
```
- Install required packages
```bash
python -m pip install -r requirements.txt
```

- Install [bandit4mal](https://github.com/lyvd/bandit4mal) (See github page)

## Usage

To list all available options:
```bash
python lastpymile.py -h
```

To scan a pacakge
```bash
python lastpymile.py <package_name>[:<package_version>]
```

## Limitations
- Binary distributions (e.g., .exe, .dmg) are not supported
- Packages that are not hosted on Github are not supported yet.

## Known Issues


## Todo (upcoming changes)
- Improve the techniques for finding Github URLs of a PyPI package. We are working to integrate [py2src](https://github.com/simonepirocca/py2src) into LastPyMile.
- Update the API documentation in the [docs](docs) directory


### How to obtain support
Contact me at [ducly.vu@unint.it](mailto:ducly.vu@unint.it) or Twitter [@vuly16](https://twitter.com/vuly16)

### Contributing
Open a Pull request at the repository in the [AssureMoss LastPyMile](https://github.com/assuremoss/lastpymile)

### Acknowledgement
This work is partly funded by the EU under the H2020 research project
[SPARTA](https://sparta.eu/) (Grant No.830892),
[AssureMOSS](https://assuremoss.eu/) (Grant No.952647) and
[CyberSec4Europe](https://cybersec4europe.eu/) (Grant No.830929).

