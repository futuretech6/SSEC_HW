.PHONY: default crackme 01 02 03 dasm zip clean

default:
	@echo "Please specify task."

crackme:
	make -C ./crackme
# make dasm

01:
	python3 exploit/01.py

02:
	python3 exploit/02.py

03:
	python3 exploit/03.py

dasm:
	file crackme/*.out
	@echo ""

	for number in 01 02 03 03_test; do \
		objdump -S crackme/$$number.out > misc/dasm-$$number.S ; \
		readelf -s crackme/$$number.out > misc/elf-$$number.txt ; \
	done

	objdump -S crackme/02_ret2libc64 > misc/dasm-02_ret2libc64.S
	readelf -s crackme/02_ret2libc64 > misc/elf-02_ret2libc64.txt
	objdump -S crackme/libc-2.27.so > misc/dasm-libc.S
	objdump -d -j .rodata crackme/libc-2.27.so > misc/rodata-libc.txt
	readelf -s crackme/libc-2.27.so > misc/elf-libc.txt

zip:
	zip -r 3180103012_陈希尧_hw02附件.zip exploit Makefile flag.txt

clean:
	make -C crackme clean
	rm -f misc/*