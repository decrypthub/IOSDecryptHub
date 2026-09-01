# IOSDecryptHub 越狱插件
#
#   make deb              同时打 rootless + roothide
#   make deb-rootless
#   make deb-roothide

VERSION := 1.24.8

deb:
	@chmod +x build_deb.sh
	./build_deb.sh all

deb-rootless:
	@chmod +x build_deb.sh
	./build_deb.sh rootless

deb-roothide:
	@chmod +x build_deb.sh
	./build_deb.sh roothide

clean:
	rm -rf build/

.PHONY: deb deb-rootless deb-roothide clean
