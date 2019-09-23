# Bitmask/Transmission docker container

Threw this together to run an isolated bitmask vpn with transmission running.

## Usage

copy `dev.env.in` to `dev.env` and fill it out with your Bitmask credentials.

Then use `bash run.sh` to start container. Once initialized, go to http://localhost:9091 and log in with user/pass `transmission/transmission`.

[bitmask-vpn]: https://0xacab.org/leap/bitmask-vpn
[transmission]: https://transmissionbt.com/
