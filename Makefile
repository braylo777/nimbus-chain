LABEL ?= local

# Run the benchmarks, write results/bench-<date>-<label>.json + results/metrics.json, regenerate README numbers.
metrics:
	python3 scripts/bench_json.py --label $(LABEL) --metrics
	python3 scripts/readme_numbers.py --write

check:
	python3 scripts/readme_numbers.py --check
	python3 scripts/count_tests.py --min 300

.PHONY: metrics check
