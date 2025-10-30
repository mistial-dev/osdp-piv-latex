PDF=osdp-document.pdf
LATEX=latexmk
LATEX_OPTS=-xelatex -interaction=nonstopmode -quiet

all: pdf

pdf:
	mkdir -p build/sections
	$(LATEX) $(LATEX_OPTS) -outdir=build main.tex
	@cp build/main.pdf $(PDF)

clean:
	rm -rf build

.PHONY: all pdf clean
