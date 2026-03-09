# 🧱 Makefile — Rendu 1 (Loca'Hub)
# Compile le rendu LaTeX avec latexmk

# Nom du fichier principal (sans extension)
MAIN = main

.PHONY: all build clean view bib

# Commande principale
all: build

# Compilation PDF avec latexmk
build:
	@echo "🚀 Compilation du rendu 1..."
	latexmk -pdf -interaction=nonstopmode $(MAIN).tex

# Nettoyage des fichiers temporaires
clean:
	@echo "🧹 Nettoyage des fichiers auxiliaires..."
	latexmk -c
	rm -f $(MAIN).bbl $(MAIN).blg *.out *.toc *.aux *.synctex.gz

# Supprime tout (même le PDF)
purge: clean
	rm -f $(MAIN).pdf

# Recompile la biblio (si bibtex)
bib:
	bibtex $(MAIN)

# Ouvre le PDF dans le viewer par défaut
view:
	xdg-open $(MAIN).pdf 2>/dev/null || open $(MAIN).pdf 2>/dev/null || start $(MAIN).pdf 2>/dev/null
