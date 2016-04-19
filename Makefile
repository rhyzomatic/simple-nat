all:
	g++ -o nftest nftest.c -lnfnetlink -lnetfilter_queue -D_BSD_SOURCE

clean:
	@rm -f nftest
