.PHONY: compile test adversarial redteam fuzz demo modelcheck faults v05 check clean

compile:
	python -m compileall -q faar test evals

test: compile
	python -m unittest discover -s test -v

adversarial: compile
	PYTHONPATH=. python evals/run_adversarial.py

redteam: compile
	PYTHONPATH=. python evals/run_redteam.py

fuzz: compile
	PYTHONPATH=. python evals/run_state_fuzz.py

demo: compile
	rm -f faar-demo.sqlite
	python -m faar.cli provision-grant --grant examples/grant.json --db faar-demo.sqlite
	python -m faar.cli mock-run --intent examples/intent.json --grant examples/grant.json --risk examples/risk.json --authority examples/authority.json --db faar-demo.sqlite
	python -m faar.cli verify-evidence --intent-id intent_demo_000000000001 --db faar-demo.sqlite

modelcheck: compile
	PYTHONPATH=. python evals/model_check_permit_protocol.py

faults: compile
	PYTHONPATH=. python evals/run_failure_injection.py

v05: compile
	PYTHONPATH=test:. python evals/run_v05_boundary.py

check: test adversarial redteam fuzz demo modelcheck faults v05

clean:
	rm -rf __pycache__ faar/__pycache__ test/__pycache__ evals/__pycache__ *.sqlite *.db build dist *.egg-info
