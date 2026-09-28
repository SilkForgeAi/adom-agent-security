.PHONY: test verify container secret-scan

test:
	python3 -B -m unittest discover -s incident_replay -p 'test_*.py'

verify:
	python3 -B incident_replay/verify.py incident_replay/results
	sha256sum -c incident_replay/MANIFEST.sha256
	sha256sum -c incident_replay/container_lab/MANIFEST.sha256

container:
	python3 -B incident_replay/container_lab/run_lab.py

secret-scan:
	@! rg -n --hidden -g '!**/.git/**' -g '!**/.venv/**' '(sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY)'

