.PHONY: default baby boy again dasm zip

default:
	@echo "Please specify task."

baby:
	python3 exploit/crack-baby.py

boy:
	python3 exploit/crack-boy.py

again:
	python3 exploit/crack-again.py

dasm:
	file crackme/bof-*
	@echo ""
	objdump -S crackme/bof-baby > misc/dasm-baby.txt
	objdump -S crackme/bof-boy > misc/dasm-boy.txt
	objdump -S crackme/bof-again > misc/dasm-again.txt
	readelf -s crackme/bof-baby > misc/elf-baby.txt
	readelf -s crackme/bof-boy > misc/elf-boy.txt
	readelf -s crackme/bof-again > misc/elf-again

zip:
	zip -r 3180103012_陈希尧_hw01附件.zip exploit Makefile flag.txt
