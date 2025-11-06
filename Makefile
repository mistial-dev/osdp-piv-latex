BUILD_DIR := build
PDF := osdp-piv-proposal.pdf
LATEX := latexmk
LATEX_OPTS := -xelatex -interaction=nonstopmode -quiet

TEX_SOURCES := main.tex \
	$(shell find sections -type f -name '*.tex') \
	$(shell find tables -type f -name '*.tex') \
	$(shell find tex -type f \( -name '*.tex' -o -name '*.cls' -o -name '*.sty' \))

all: pdf

pdf: $(PDF)

$(PDF): $(TEX_SOURCES) Makefile | $(BUILD_DIR)/sections
	$(LATEX) $(LATEX_OPTS) -outdir=$(BUILD_DIR) main.tex
	cp $(BUILD_DIR)/main.pdf $(PDF)

$(BUILD_DIR)/sections:
	mkdir -p $(BUILD_DIR)/sections

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(PDF)

.PHONY: all pdf clean
