# PyPhone

TUI softhone using Python3 and PJSIP.

## Getting Started

Pjproject guide to build PJSUA and PJSUA2: [Guide](https://docs.pjsip.org/en/latest/pjsua2/building.html)

### Install

```shell
# Clone the pyphone repository
git clone https://github.com/oornnery/pyphone.git
cd pyphone
# Clone the pjproject repository
git clone https://github.com/pjsip/pjproject.git
cd pjproject
# Build PJSIP
./configure CFLAGS="-fPIC"
make dep && make && sudo make install
# Build to python
sudo apt-get install swig build-essential python3-dev libasound2-dev
cd pjsip-apps/src/swig/python
make && sudo make install
# Test the installation
python -c 'import pjsua'
# If it works, you can run the example
```

### Settings and Configuration

Edit the `.env` file to configure you SIP credentials.

```shell
USERNAME=''
PASSWORD=''
DOMAIN=''
PORT=0
```

### Running

```shell
python pyphone/_pjsip.py
```

## References

- [Pjproject](https://github.com/pjsip/pjproject)
- [PJproject docs](https://docs.pjsip.org/en/latest/)
- [PJSUA Python3](https://github.com/mgwilliams/python3-pjsip)
