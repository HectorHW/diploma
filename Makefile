.PHONY: build
build:
	xelatex -synctex=1 -interaction=nonstopmode main.tex
	biber main
	xelatex -synctex=1 -interaction=nonstopmode main.tex
	xelatex -synctex=1 -interaction=nonstopmode main.tex

.PHONY: images
images:
	plantuml images/*.puml