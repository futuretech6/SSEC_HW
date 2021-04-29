.PHONY: default echo1 echo2 echo3 01 02 03 01_fmt32 02_fmt64 03_bonus
.PHONY: aslr dasm zip file clean

export TOP=$(shell pwd)
export CRACKME=${TOP}/crackme
export LD_LIBRARY_PATH:=${LD_LIBRARY_PATH}:${CRACKME}/01_fmt32:${CRACKME}/02_fmt64:${CRACKME}/03_bonus
# export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/home/student/SS/HW/hw03/crackme/01_fmt32:/home/student/SS/HW/hw03/crackme/02_fmt64:/home/student/SS/HW/hw03/crackme/03_bonus

default:
	@echo "\e[32mLD_LIBRARY_PATH:\e[0m ${LD_LIBRARY_PATH}"
	@echo "\e[32mkernel.randomize_va_space:\e[0m $(shell sysctl -n kernel.randomize_va_space)"
	@echo "\nPlease specify task."

aslr:
	@if [ $(shell sysctl -n kernel.randomize_va_space) -eq 2 ] ; then \
		sudo sysctl -w kernel.randomize_va_space=0 ; \
	else \
		sudo sysctl -w kernel.randomize_va_space=2 ; \
	fi

echo1:
	crackme/01_fmt32/echo
echo2:
	crackme/02_fmt64/echo
echo3:
	crackme/03_bonus/echo

01: 01_fmt32
01_fmt32:
	python3 exploit/01_fmt32.py
02: 02_fmt64
02_fmt64:
	python3 exploit/02_fmt64.py
03: 03_bonus
03_bonus:
	python3 exploit/03_bonus.py

file:
	@for i in 01_fmt32 02_fmt64 03_bonus ; do \
		echo "" ; \
		ls crackme/$$i/* | xargs file ; \
		echo "" ; \
	done

dasm:
	@echo "\e[32mDisassembling...\e[0m"
	@for i in 01_fmt32 02_fmt64 03_bonus ; do \
		objdump -S crackme/$$i/echo > misc/$$i/dasm-echo.S ; \
		readelf -s crackme/$$i/echo > misc/$$i/elf-echo.txt ; \
		if [ crackme/$$i -ef crackme/03_bonus ] ; then \
			objdump -S crackme/$$i/libc.so > misc/$$i/dasm-libc.S ; \
			readelf -s crackme/$$i/libc.so > misc/$$i/elf-libc.txt ; \
		else \
			objdump -S crackme/$$i/libtarget.so > misc/$$i/dasm-libtarget.S ; \
			readelf -s crackme/$$i/libtarget.so > misc/$$i/elf-libtarget.txt ; \
		fi ; \
		python3 -c "from pwn import ELF; import sys; sys.stdout = open('got_tmp.json', 'w'); print(ELF('crackme/$$i/echo').got)" ; \
		sed -i "s/'/\"/g" got_tmp.json ; \
		python3 -m json.tool --sort-keys got_tmp.json misc/$$i/got.json ; \
	done
	@rm got_tmp.json
	@echo "\e[32mDone.\e[0m"

zip:
	zip -r 3180103012_陈希尧_hw03附件.zip exploit Makefile flag.txt

clean:
	rm misc/**/*