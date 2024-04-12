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
# git clone https://github.com/pjsip/pjproject.git
# unzip the pjproject
tar -xvf pjproject-2.14.1.tar.gz
cd pjproject-2.14.1
# Build PJSIP
./configure CFLAGS="-fPIC"
make dep && make && sudo make install
```

### Build to python3

Install dependencies.

```shell
sudo apt-get install swig build-essential python3-dev libasound2-dev
```

Official build to python3:

```shell
# Build to python
cd pjsip-apps/src/swig/python
# Clone the build to python 3
make && sudo make install
```

Alternatively, you can build to python3 with the following command.

```shell
# Build to python
cd pjsip-apps/src/
# Clone the build to python 3
git clone https://github.com/mgwilliams/python3-pjsip.git
cd python3-pjsip
# Install pjsua
python3 setup.py build
sudo python3 setup.py install
```

Test import pjsua to python firstly.

```shell
python3 -c "import pjsua"
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
