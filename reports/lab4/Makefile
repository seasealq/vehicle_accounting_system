.PHONY: pdf clean

pdf:
	cd figures && xelatex -interaction=nonstopmode -halt-on-error secure_architecture.tex
	xelatex -interaction=nonstopmode -halt-on-error report.tex
	xelatex -interaction=nonstopmode -halt-on-error report.tex

clean:
	rm -f report.aux report.log report.out report.toc report.synctex.gz
	rm -f figures/secure_architecture.aux figures/secure_architecture.log figures/secure_architecture.out
