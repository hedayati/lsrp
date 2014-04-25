all: router sfta

router: router.c
	gcc -o router router.c -lpthread
	
sfta: sfta.c
	gcc -o sfta sfta.c -lpthread
	
clean:
	rm -rf router sfta *.o
