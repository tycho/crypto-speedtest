# $Id$

pdfs: baseplots sidebysideplots

baseplots:
	PLOTNAME=p2-300-debian-etch ./speedtest.gnuplot
	PLOTNAME=p3-1000-ubuntu-gutsy ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-etch ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-lenny ./speedtest.gnuplot
	PLOTNAME=p4-3200-gentoo ./speedtest.gnuplot
	PLOTNAME=p4-3200-ubuntu-gutsy ./speedtest.gnuplot

PAGELIST=`for p in \`seq 1 26\`; do echo A$$p B$$p C$$p D$$p E$$p F$$p; done`

sidebysideplots:
# Make other plots which will fill an A4 paper

	PLOTNAME=p2-300-debian-etch FILENAME=p2-300-debian-etch-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p3-1000-ubuntu-gutsy FILENAME=p3-1000-ubuntu-gutsy-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-etch FILENAME=p4-3200-debian-etch-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-debian-lenny FILENAME=p4-3200-debian-lenny-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-gentoo FILENAME=p4-3200-gentoo-a4 PAPER=a4 ./speedtest.gnuplot
	PLOTNAME=p4-3200-ubuntu-gutsy FILENAME=p4-3200-ubuntu-gutsy-a4 PAPER=a4 ./speedtest.gnuplot

# Extract pages in order from each pdf
	pdftk \
		A=p2-300-debian-etch-a4.pdf B=p3-1000-ubuntu-gutsy-a4.pdf \
		C=p4-3200-debian-etch-a4.pdf D=p4-3200-debian-lenny-a4.pdf \
		E=p4-3200-gentoo-a4.pdf F=p4-3200-ubuntu-gutsy-a4.pdf \
		cat $(PAGELIST) output sidebyside-comparision.pdf

# Put all pages with same graph onto one for quick comparison
	pdfnup --nup 2x3 --orient portrait --paper a4paper --frame true sidebyside-comparision.pdf
	mv sidebyside-comparision-2x3.pdf sidebyside-comparision.pdf

	rm p2-300-debian-etch-a4.pdf p3-1000-ubuntu-gutsy-a4.pdf p4-3200-debian-etch-a4.pdf
	rm p4-3200-debian-lenny-a4.pdf p4-3200-gentoo-a4.pdf p4-3200-ubuntu-gutsy-a4.pdf

EXTRA_DIST = \
	README \
	speedtest.gnuplot \
	*.pdf \
	p2-300-debian-etch/*.txt \
	p3-1000-ubuntu-gutsy/*.txt \
	p4-3200-debian-etch/*.txt \
	p4-3200-debian-lenny/*.txt \
	p4-3200-gentoo/*.txt \
	p4-3200-ubuntu-gutsy/*.txt
