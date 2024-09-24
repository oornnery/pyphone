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
poetry install
poetry run
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

## Alternatives
