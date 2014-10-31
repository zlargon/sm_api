all: khttp test

khttp:
	$(MAKE) -C lib/khttp

test:
	$(MAKE) -C test

clean:
	$(MAKE) -C lib/khttp clean
	$(MAKE) -C test clean

.PHONY: khttp test
