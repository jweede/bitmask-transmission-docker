
docker_scripts/bitmask-dev-requirements.txt: poetry.lock
	poetry export --without-hashes -o $@
