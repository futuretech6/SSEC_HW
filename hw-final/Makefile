.PHONY: default 01 02 03 01_harmshell 02_harmrop 03_harmheap
.PHONY: dasm zip

export TOP=$(shell pwd)
export CRACKME=${TOP}/crackme

01: 01_harmshell
01_harmshell:
	python3 exploit/01_harmshell.py

02: 02_harmrop
02_harmrop:
	python3 exploit/02_harmrop.py

03: 03_harmheap
03_harmheap:
	python3 exploit/03_harmheap.py

dasm:
	@mkdir -p misc
	@echo "\e[32mDisassembling...\e[0m"
	arm-linux-gnueabi-objdump -S crackme/02*/camera_app > misc/2-dasm.S
	arm-linux-gnueabi-readelf -s crackme/02*/camera_app > misc/2-sym.txt
	arm-linux-gnueabi-objdump -S crackme/03*/camera_app > misc/3-dasm.S
	arm-linux-gnueabi-readelf -s crackme/03*/camera_app > misc/3-sym.txt
	arm-linux-gnueabi-objdump -S crackme/03*/camera_app.debug > misc/3_dbg-dasm.S
	arm-linux-gnueabi-readelf -s crackme/03*/camera_app.debug > misc/3_dbg-sym.txt
	@echo "\e[32mDone.\e[0m"

zip:
	rm -f 3180103012_陈希尧_final附件.zip
	zip -r 3180103012_陈希尧_final附件.zip exploit Makefile flag.txt
