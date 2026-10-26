# InkBlade developer / release entry points.
#
#   make help          list targets
#   make test          full unittest suite
#   make audit         full pre-release self-audit (compile + hygiene + tests + verify)
#   make build         wheel + sdist into dist/
#   make sbom          CycloneDX SBOM for the artifacts in dist/
#   make sign          cosign keyless signature bundles for dist/
#
# On Windows without make, use the PowerShell equivalents in scripts/release/.

PY ?= python
OUT ?= dist
TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null)

.PHONY: help install test compile public-tree vendor sdk-test audit verify \
        build sbom checksums sign docker helm-lint dry-run clean

help:
	@echo "InkBlade make targets"
	@echo "  install       editable install (pip install -e .)"
	@echo "  test          public test subset (tests/public-subset.txt)"
	@echo "  compile       byte-compile the first-party package"
	@echo "  public-tree   repository hygiene scan (must report 0 hits)"
	@echo "  vendor        vendored web asset checksum verification"
	@echo "  sdk-test      plugin SDK contract tests"
	@echo "  verify        release hygiene gate (metadata/docs/helm/sdk)"
	@echo "  audit         compile + public-tree + vendor + factory tests + verify"
	@echo "  build         build wheel and sdist into $(OUT)/"
	@echo "  sbom          CycloneDX SBOM for $(OUT)/ artifacts"
	@echo "  checksums     write $(OUT)/SHA256SUMS"
	@echo "  sign          cosign keyless sign $(OUT)/* (needs cosign + OIDC)"
	@echo "  docker        docker build -t inkblade:$(TAG) ."
	@echo "  helm-lint     helm lint deploy/helm/inkblade"
	@echo "  dry-run       offline rehearsal (pilot --dry-run into $(OUT)/dry-run)"
	@echo "  clean         remove $(OUT)/ and bytecode caches"

install:
	$(PY) -m pip install -e .

test:
	$(PY) scripts/run-public-tests.py -v

compile:
	$(PY) scripts/release/compile-check.py

public-tree:
	$(PY) scripts/check-public-tree.py --root .

vendor:
	$(PY) -m unittest tests.test_vendor_checksums -v

sdk-test:
	$(PY) -m unittest tests.test_sdk -v

verify:
	$(PY) scripts/release/verify.py

audit: compile public-tree vendor verify
	$(PY) scripts/run-public-tests.py

build:
	$(PY) scripts/release/build.py --out $(OUT) --clean

sbom:
	$(PY) scripts/release/sbom.py --dist $(OUT) --out $(OUT)/sbom.cdx.json

checksums:
	$(PY) -c "import hashlib,pathlib;d=pathlib.Path('$(OUT)');rows=[(hashlib.sha256(p.read_bytes()).hexdigest(),p.name) for p in sorted(d.iterdir()) if p.is_file() and p.name!='SHA256SUMS'];d.joinpath('SHA256SUMS').write_text(''.join(f'{h}  {n}\n' for h,n in rows),encoding='utf-8');print(f'checksums: {len(rows)} files')"

sign:
	$(PY) scripts/release/sign.py --dist $(OUT)

docker:
	docker build -t inkblade:$(TAG) .

helm-lint:
	helm lint deploy/helm/inkblade
	helm template inkblade deploy/helm/inkblade --namespace inkblade > /dev/null

dry-run:
	$(PY) -m inkblade pilot --dry-run --out $(OUT)/dry-run

clean:
	rm -rf $(OUT) build
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
