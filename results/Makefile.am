# $Id$

pdfs: baseplots sidebysideplots

baseplots:
	PLOTNAME=p2-300-debian-etch ./speedtest.gnuplot
	PLOTNAME=p3-1000-debian-etch ./speedtest.gnuplot
	PLOTNAME=cel-2660-debian-etch ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-etch ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-lenny ./speedtest.gnuplot
	PLOTNAME=p4-3200-gentoo ./speedtest.gnuplot
	PLOTNAME=p4-3200-ubuntu-gutsy ./speedtest.gnuplot
	PLOTNAME=p4-3200-fedora8 ./speedtest.gnuplot
	./distrospeed.gnuplot

PAGELIST4=`for p in \`seq 1 22\`; do echo A$$p B$$p C$$p D$$p; done`

PAGELIST8=`for p in \`seq 1 22\`; do echo A$$p B$$p C$$p D$$p E$$p F$$p G$$p H$$p; done`

sidebysideplots:
# Make other plots which will fill an A4 paper

	PLOTNAME=p2-300-debian-etch FILENAME=p2-300-debian-etch-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p3-1000-debian-etch FILENAME=p3-1000-debian-etch-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=cel-2660-debian-etch FILENAME=cel-2660-debian-etch-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-etch FILENAME=p4-3200-debian-etch-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-lenny FILENAME=p4-3200-debian-lenny-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-gentoo FILENAME=p4-3200-gentoo-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-ubuntu-gutsy FILENAME=p4-3200-ubuntu-gutsy-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-fedora8 FILENAME=p4-3200-fedora8-a4 PAPER=a4 ./speedtest.gnuplot

# Extract pages in order from each pdf
	pdftk \
		A=p2-300-debian-etch-a4.pdf B=p3-1000-debian-etch-a4.pdf \
		C=cel-2660-debian-etch-a4.pdf D=p4-3200-debian-etch-a4.pdf \
		E=p4-3200-ubuntu-gutsy-a4.pdf F=p4-3200-debian-lenny-a4.pdf \
		G=p4-3200-gentoo-a4.pdf H=p4-3200-fedora8-a4.pdf  \
		cat $(PAGELIST8) output sidebyside-comparison.pdf

# Put all pages with same graph onto one for quick comparison
	pdfnup --nup 2x4 --orient portrait --paper a4paper --frame true sidebyside-comparison.pdf

# Extract pages in a different order from each pdf
	pdftk \
		A=p2-300-debian-etch-a4.pdf B=p3-1000-debian-etch-a4.pdf \
		C=p4-3200-ubuntu-gutsy-a4.pdf D=p4-3200-debian-lenny-a4.pdf \
		E=cel-2660-debian-etch-a4.pdf F=p4-3200-debian-etch-a4.pdf \
		G=p4-3200-gentoo-a4.pdf H=p4-3200-fedora8-a4.pdf  \
		cat $(PAGELIST8) output sidebyside-comparison.pdf

	pdflatex -halt-on-error sidebyside-comparison-4x2.tex
	rm sidebyside-comparison.pdf

# Extract debian-etch pages in order from each pdf
	pdftk \
		A=p2-300-debian-etch-a4.pdf B=p3-1000-debian-etch-a4.pdf \
		C=cel-2660-debian-etch-a4.pdf D=p4-3200-debian-etch-a4.pdf \
		cat $(PAGELIST4) output cpu-comparison.pdf

# Put all pages with same graph onto one for quick comparison
	pdfnup --nup 2x2 --orient landscape --paper a4paper --frame true cpu-comparison.pdf

	rm p2-300-debian-etch-a4.pdf p3-1000-debian-etch-a4.pdf cel-2660-debian-etch-a4.pdf
	rm p4-3200-debian-etch-a4.pdf p4-3200-debian-lenny-a4.pdf p4-3200-gentoo-a4.pdf
	rm p4-3200-ubuntu-gutsy-a4.pdf p4-3200-fedora8-a4.pdf

pngplots:
	for pdf in *.pdf; do \
	    echo Exploding $$pdf; \
	    pdftoppm -r 200 $$pdf $${pdf%%.pdf}; \
	    for p in $${pdf%%.pdf}-*.ppm; do \
	        echo Converting $$p to PNG; \
	        convert $$p $${p%%.ppm}.png; \
	        rm -f $$p; \
	    done; \
	done

EXTRA_DIST = \
	README \
	speedtest.gnuplot \
	distrospeed.gnuplot \
	*.pdf \
	p2-300-debian-etch/*.txt \
	p3-1000-debian-etch/*.txt \
	cel-2660-debian-etch/*.txt \
	p4-3200-debian-etch/*.txt \
	p4-3200-debian-lenny/*.txt \
	p4-3200-gentoo/*.txt \
	p4-3200-ubuntu-gutsy/*.txt \
	p4-3200-fedora8/*.txt
