all:
	g++ -o nftest nftest.c checksum.c -lnfnetlink -lnetfilter_queue -D__USE_MISC

clean:
	@rm -f nftest
