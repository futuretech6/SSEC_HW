.PHONY: default 02 03 02_uaf 03_unsafe_unlink
.PHONY: dasm zip

export TOP=$(shell pwd)
export CRACKME=${TOP}/crackme

02: 02_uaf
02_uaf:
	python3 exploit/02_uaf.py
03: 03_unsafe_unlink
03_unsafe_unlink:
	python3 exploit/03_unsafe_unlink.py

dasm:
	@mkdir -p misc/02_uaf misc/03_unsafe_unlink
	@echo "\e[32mDisassembling...\e[0m"
	objdump -S crackme/02_uaf/uaf > misc/02_uaf/dasm-uaf.S
	readelf -s crackme/02_uaf/uaf > misc/02_uaf/elf-uaf.txt
	objdump -S crackme/02_uaf/libc-2.27.so > misc/02_uaf/dasm-libc.S
	readelf -s crackme/02_uaf/libc-2.27.so > misc/02_uaf/elf-libc.txt
	objdump -S crackme/03_unsafe_unlink/unsafe_unlink > misc/03_unsafe_unlink/dasm-unsafe_unlink.S
	readelf -s crackme/03_unsafe_unlink/unsafe_unlink > misc/03_unsafe_unlink/elf-unsafe_unlink.txt
	objdump -S crackme/03_unsafe_unlink/libc-2.27.so > misc/03_unsafe_unlink/dasm-libc.S
	readelf -s crackme/03_unsafe_unlink/libc-2.27.so > misc/03_unsafe_unlink/elf-libc.txt
	@echo "\e[32mDone.\e[0m"

zip:
	rm -f 3180103012_陈希尧_hw04附件.zip
	zip -r 3180103012_陈希尧_hw04附件.zip exploit Makefile flag.txt
