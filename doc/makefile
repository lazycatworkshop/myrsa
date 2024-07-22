
SOURCES=$(wildcard *.tex)
TARGETS=$(SOURCES:.tex=.pdf)

all: $(TARGETS)

%.pdf: %.tex
	pdflatex $<
	pdflatex $<  # Run twice for TOC

clean:
	rm -rf *.aux *.log *.pdf *.dvi *.out *.toc *.synctex.gz *.fdb_latexmk *.fls
