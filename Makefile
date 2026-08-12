BUILD_DIR := build
PDF := osdp-piv-proposal.pdf
LATEX := latexmk
LATEX_OPTS := -xelatex -interaction=nonstopmode -quiet
PIV_PROFILES ?= 9e-rsa1024

TEX_SOURCES := main.tex \
	$(shell find sections -type f -name '*.tex') \
	$(shell find tables -type f -name '*.tex') \
	$(shell find tex -type f \( -name '*.tex' -o -name '*.cls' -o -name '*.sty' \))

all: pdf

test:
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts python3 -m unittest discover -s scripts/tests -p 'test_*.py'

live-piv-auto:
	PIV_PROFILES="$(PIV_PROFILES)" scripts/load_ykman_committed_material.sh

pdf: $(PDF)

redline:
	@if [ -z "$(BASE)" ]; then echo "Usage: make redline BASE=<git-ref>" >&2; exit 2; fi
	bash scripts/build_redline.sh "$(BASE)"

$(PDF): $(TEX_SOURCES) Makefile | $(BUILD_DIR)/sections
	$(LATEX) $(LATEX_OPTS) -outdir=$(BUILD_DIR) main.tex
	cp $(BUILD_DIR)/main.pdf $(PDF)

$(BUILD_DIR)/sections:
	mkdir -p $(BUILD_DIR)/sections

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(PDF)

.PHONY: all test live-piv-auto pdf redline clean
