# PyPhone

TUI softhone using Python3 and PJSIP.

## Getting Started

Pjproject guide to build PJSUA and PJSUA2: [Guide](https://docs.pjsip.org/en/latest/pjsua2/building.html)

### Install

Install dependencies (Ubuntu 22.04 LTS).

```shell
sudo apt update
sudo apt install swig build-essential python3-dev libasound2-dev libssl3 libssl-dev ffmpeg libv4l-dev libv4l-0 alsa-oss alsa-utils  pulseaudio pulseaudio-utils libyuv0 libyuv-dev libsdl2-2.0-0 libsdl2-dev libx264-dev
```

Build PJSIP.

```shell
./install.sh
```

Manual Build PJSIP

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
./configure --disable-video --disable-v4l2 CFLAGS="-fPIC" CXXFLAGS="-fPIC"
make dep && make
sudo make install
```

Build PJSUA2 to python3.

```shell
# Build to python
cd pjsip-apps/src/swig/python
make
sudo make install
pip install .
# Poetry alternative
# poetry add .
```

Test import pjsua to python firstly.

```shell
python3 -c "import pjsua2"
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
python pyphone/main.py
```

## References

- [Pjproject](https://github.com/pjsip/pjproject)
- [PJproject docs](https://docs.pjsip.org/en/latest/)
- [PJSUA Python3](https://github.com/mgwilliams/python3-pjsip)
