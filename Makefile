
build: code images build-tex merge

practice: code images build-practice-tex merge-practice

.PHONY: titlepage
titlepage:
	xelatex -synctex=1 -interaction=nonstopmode titlepage-main.tex
	mv titlepage-main.pdf титульный\ лист\ Редькин.pdf

.PHONY: build-tex
build-tex:
	xelatex -synctex=1 -interaction=nonstopmode main.tex
	biber main
	xelatex -synctex=1 -interaction=nonstopmode main.tex
	xelatex -synctex=1 -interaction=nonstopmode main.tex

.PHONY: images
images:
	plantuml images/*.puml

.PHONY: build-practice-tex
build-practice-tex:
	xelatex -synctex=1 -interaction=nonstopmode practice.tex
	biber practice
	xelatex -synctex=1 -interaction=nonstopmode practice.tex
	xelatex -synctex=1 -interaction=nonstopmode practice.tex
	

.PHONY: merge-practice
merge-practice:
	mv practice.pdf practice-pages.pdf
	pdftk A=practice-titlepage.pdf B=practice-pages.pdf cat A1 B1-end output practice.pdf

.PHONY: code
code:
	rustfmt +nightly code/execution.rs

.PHONY: merge
merge:
	pdftk A=main.pdf B=titlepage-signed.pdf cat B1 A2-end output diplom.pdf

.PHONY: extract-antiplagiat
extract-antiplagiat:
	pdftk diplom.pdf cat 2-32 36 output vsredkin-for-antiplagiat.pdf

antiplagiat: build extract-antiplagiat

.PHONY: presentation
presentation:
	xelatex -synctex=1 -interaction=nonstopmode presentation.tex
