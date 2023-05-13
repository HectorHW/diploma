.PHONY: build
build:
	xelatex -synctex=1 -interaction=nonstopmode main.tex
	biber main
	xelatex -synctex=1 -interaction=nonstopmode main.tex
	xelatex -synctex=1 -interaction=nonstopmode main.tex

.PHONY: images
images:
	plantuml images/*.puml

.PHONY: practice
practice:
	xelatex -synctex=1 -interaction=nonstopmode practice.tex
	biber practice
	xelatex -synctex=1 -interaction=nonstopmode practice.tex
	xelatex -synctex=1 -interaction=nonstopmode practice.tex
	mv practice.pdf practice-pages.pdf
	pdftk A=practice-titlepage.pdf B=practice-pages.pdf cat A1 B1-end output practice.pdf

