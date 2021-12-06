# lastpymile

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
python -m pip install -r requirements
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