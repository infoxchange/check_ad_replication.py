
test:	test_ok test_fail test_fail_v test_fail_stale test_fail_stale_v clean

test_ok:
	-@rm -f test_fifo
	-@mkfifo test_fifo
	( cat net.ads.info.txt > test_fifo ; sleep 0.1; sed -e "s/Wed.*AEDT/`date -d '-1 hour' +'%a %h %d %H:%M:%S %Y %Z'`/" samba-tool.drs.showrepl.OK.txt > test_fifo ) &
	../check_ad_replication.py -T test_fifo

test_fail:
	-@rm -f test_fifo
	-@mkfifo test_fifo
	( cat net.ads.info.txt > test_fifo ; sleep 0.1; sed -e "/success/ s/Wed.*AEDT/`date -d '-1 hour' +'%a %h %d %H:%M:%S %Y %Z'`/"  -e "/failed/ s/Wed.*AEDT/`date -d '-5 mins' +'%a %h %d %H:%M:%S %Y %Z'`/" samba-tool.drs.showrepl.fail.txt > test_fifo ) &
	../check_ad_replication.py -T test_fifo && exit 1 || exit 0

test_fail_v:
	-@rm -f test_fifo
	-@mkfifo test_fifo
	( cat net.ads.info.txt > test_fifo ; sleep 0.1; sed -e "/success/ s/Wed.*AEDT/`date -d '-5 minutes' +'%a %h %d %H:%M:%S %Y %Z'`/"  -e "/failed/ s/Wed.*AEDT/`date -d '-5 mins' +'%a %h %d %H:%M:%S %Y %Z'`/" samba-tool.drs.showrepl.fail.txt > test_fifo ) &
	../check_ad_replication.py -v -T test_fifo && exit 1 || exit 0

test_fail_stale:
	-@rm -f test_fifo
	-@mkfifo test_fifo
	( cat net.ads.info.txt > test_fifo ; sleep 0.1; sed -e "/success/ s/Wed.*AE[SD]T/`date -d '-5 minutes' +'%a %h %d %H:%M:%S %Y %Z'`/"  -e "/failed/ s/Wed.*AEDT/`date -d '-5 mins' +'%a %h %d %H:%M:%S %Y %Z'`/" samba-tool.drs.showrepl.stale_dc.txt > test_fifo ) &
	../check_ad_replication.py -T test_fifo && exit 1 || exit 0

test_fail_stale_v:
	-@rm -f test_fifo
	-@mkfifo test_fifo
	( cat net.ads.info.txt > test_fifo ; sleep 0.1; sed -e "/success/ s/Wed.*AE[SD]T/`date -d '-5 minutes' +'%a %h %d %H:%M:%S %Y %Z'`/"  -e "/failed/ s/Wed.*AEDT/`date -d '-5 mins' +'%a %h %d %H:%M:%S %Y %Z'`/" samba-tool.drs.showrepl.stale_dc.txt > test_fifo ) &
	../check_ad_replication.py -v -T test_fifo && exit 1 || exit 0


clean:
	@rm test_fifo
