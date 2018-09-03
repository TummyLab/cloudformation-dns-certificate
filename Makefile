.PHONY: default
default: cloudformation.json cloudformation.yaml ;

certificate_min.py: certificate.py
	venv/bin/pyminify certificate.py | tail -n '+2' > certificate_min.py

cloudformation.json: cloudformation.py certificate_min.py
	venv/bin/python cloudformation.py

cloudformation.yaml: cloudformation.py certificate_min.py
	venv/bin/python cloudformation.py
