# IOSDecryptHub — 完整源码仓
#
# 本仓同时包含:
#   * 运行时分析引擎 dylib 的全部源码 (src/, 含第三方 fishhook / Capstone)
#   * 越狱加载器 (src/loader.m)、管理器 App (app/)、updater daemon (daemon/)
#   * 打包脚本 (build_deb.sh) 与发布产物 (vendor/)
#
# ---------- 常用命令 ----------
#   make                       编译引擎 (dev 变体, arm64)
#   make VARIANT=trollstore    编译巨魔变体 (arm64) —— Release 里那个 dylib 资产
#   make VARIANT=rootless      编译越狱变体 (arm64) —— deb 包里的引擎
#   make dist                  产出带版本号的 decrypt_helper-<version>.dylib
#   make deb                   打 rootless + roothide 两个越狱 deb
#   make test-updater          仿真回归测试 (线上 release 走完整更新链路)
#
# 也可在 Linux/WSL 交叉编译: 需设置 IOS_SDK 指向 iPhoneOS SDK,
# CROSS_CC 指向支持 Apple target 的 clang, 然后 make linux。
#
# 依赖: macOS + Xcode (xcrun); 打 deb 另需 dpkg-deb / ldid / install_dylib

VERSION := 1.27.5
TARGET  := decrypt_helper.dylib

# Capstone 反汇编库源文件（仅 ARM/ARM64 架构）
CAPSTONE_SRC := src/core/capstone/cs.c \
                src/core/capstone/utils.c \
                src/core/capstone/SStream.c \
                src/core/capstone/MCInst.c \
                src/core/capstone/MCInstrDesc.c \
                src/core/capstone/MCRegisterInfo.c \
                src/core/capstone/Mapping.c \
                src/core/capstone/arch/ARM/ARMDisassembler.c \
                src/core/capstone/arch/ARM/ARMInstPrinter.c \
                src/core/capstone/arch/ARM/ARMMapping.c \
                src/core/capstone/arch/ARM/ARMModule.c \
                src/core/capstone/arch/AArch64/AArch64BaseInfo.c \
                src/core/capstone/arch/AArch64/AArch64Disassembler.c \
                src/core/capstone/arch/AArch64/AArch64InstPrinter.c \
                src/core/capstone/arch/AArch64/AArch64Mapping.c \
                src/core/capstone/arch/AArch64/AArch64Module.c

SRC     := src/core/fishhook.c \
           src/core/dh_health.c \
           src/core/dh_capture.c \
           src/core/dh_capability.c \
           src/core/dh_thunk.m \
           src/core/dh_noise.m \
           src/core/dh_spoof.m \
           src/core/dh_symtab.c \
           src/core/dh_dlsym_redirect.c \
           src/core/log_store.m \
           src/core/zip_writer.c \
           src/core/macho_dump.m \
           src/core/dump_manager.m \
           src/core/dh_files.m \
           src/core/analysis.m \
           src/hooks/crypto/hook_digest.m \
           src/hooks/crypto/hook_hmac.m \
           src/hooks/crypto/hook_symmetric.m \
           src/hooks/crypto/hook_asymmetric.m \
           src/hooks/crypto/hook_kdf.m \
           src/hooks/crypto/hook_evp.m \
           src/hooks/behavior/hook_file.m \
           src/hooks/behavior/hook_system.m \
           src/hooks/behavior/hook_keychain.m \
           src/hooks/behavior/hook_env.m \
           src/hooks/behavior/hook_spoof_objc.m \
           src/hooks/behavior/hook_dyld.m \
           src/hooks/behavior/hook_network.m \
           src/hooks/behavior/hook_webkit.m \
           src/server/http_server.m \
           src/server/mcp_server.m \
           src/server/dh_log_json.m \
           src/ui/ui_float.m \
           src/core/main.m \
           $(CAPSTONE_SRC)

FRAMEWORKS := -framework Foundation -framework UIKit -framework CoreGraphics -framework Security

# Capstone 编译宏 (缺一不可, 否则运行时失败):
#   CAPSTONE_USE_SYS_DYN_MEM — 用系统 malloc/free, 否则 cs_open 返回 CS_ERR_MEMSETUP
#   CAPSTONE_HAS_ARM / _ARM64 — 注册 ARM/AArch64 架构, 否则 cs_open 返回 CS_ERR_ARCH
CAPSTONE_DEF := -DCAPSTONE_USE_SYS_DYN_MEM -DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_ARM64
VERSION_DEF := -DDH_VERSION_STR=\"$(VERSION)\"

# ---------- 打包变体矩阵 ----------
# 一份源码编出 4 个变体, 差别只有编译期 -DDH_VARIANT 编号 (见 src/core/dh_capability.c)。
# 该编号目前只影响 MCP get_capabilities 握手自报的 variant 字段, 能力位不随变体改变。
# 编号 0/1/2 已是已发布产物的既有语义, 不得重排; 新增只能往后追加。
#   make                       -> dev        (0) 开发者手动注入 / DYLD_INSERT
#   make VARIANT=trollstore    -> trollstore (1) 巨魔注入器 —— Release 里的 dylib 资产
#   make VARIANT=rootless      -> rootless   (2) 越狱 rootless 包
#   make VARIANT=roothide      -> roothide   (3) 越狱 roothide 包 (胖切片 arm64+arm64e)
VARIANT ?= dev

ifeq ($(VARIANT),dev)
    DH_VARIANT_NUM := 0
    ARCH    := arm64
    MIN_IOS := 14.0
else ifeq ($(VARIANT),trollstore)
    DH_VARIANT_NUM := 1
    ARCH    := arm64
    MIN_IOS := 14.0
else ifeq ($(VARIANT),rootless)
    DH_VARIANT_NUM := 2
    ARCH    := arm64
    MIN_IOS := 14.0
else ifeq ($(VARIANT),roothide)
    DH_VARIANT_NUM := 3
    ARCH    := arm64
    MIN_IOS := 14.0
else
    $(error 未知 VARIANT=$(VARIANT); 可选: dev / trollstore / rootless / roothide)
endif

# ---------- 1) iOS 真机 dylib (默认 target) ----------
SDK     := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
CC      := $(shell xcrun --find clang)
ARCHS   ?= $(ARCH)
ARCH_FLAGS := $(foreach A,$(ARCHS),-arch $(A))
INCLUDES := -Isrc/core -Isrc/core/capstone/include -Isrc/hooks/crypto -Isrc/hooks/behavior -Isrc/server -Isrc/ui
WEB_HEADER := src/server/web_index_html.h
WECHAT_HEADER := src/server/web_wechat_png.h
WEB_ASSETS := $(WEB_HEADER) $(WECHAT_HEADER)

CFLAGS  := $(ARCH_FLAGS) \
           -isysroot $(SDK) \
           -miphoneos-version-min=$(MIN_IOS) \
           -dynamiclib \
           -install_name @executable_path/$(TARGET) \
           -ObjC -fobjc-arc \
           -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
           -O2 \
           $(INCLUDES) \
           $(CAPSTONE_DEF) \
           $(VERSION_DEF) \
           -DDH_VARIANT=$(DH_VARIANT_NUM) \
           $(FRAMEWORKS)

all: $(TARGET)

$(WEB_HEADER): web/index.html tools/gen_web.py
	python3 tools/gen_web.py web/index.html $(WEB_HEADER)

$(WECHAT_HEADER): web/wechat-follow.png tools/gen_web.py
	python3 tools/gen_web.py web/wechat-follow.png $(WECHAT_HEADER) kDHWeChatPNG

$(TARGET): $(WEB_ASSETS) $(SRC) Makefile
	@if [ -z "$(SDK)" ]; then echo "❌ 没找到 iPhoneOS SDK (xcrun --sdk iphoneos)"; exit 1; fi
	@echo "[*] 编译 iOS dylib (VARIANT=$(VARIANT), archs=$(ARCHS), min=$(MIN_IOS))..."
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)
	@echo "✅ $(TARGET)"

# ---------- 2) Linux 交叉编译 (WSL) ----------
# 需自备 iPhoneOS SDK 与支持 Apple target 的 clang:
#   export IOS_SDK=/path/to/iPhoneOS17.x.sdk
#   export CROSS_CC=/path/to/clang
linux:
	@if [ -z "$(IOS_SDK)" ] || [ -z "$(CROSS_CC)" ]; then \
		echo "❌ 需设置 IOS_SDK (iPhoneOS SDK 路径) 和 CROSS_CC (支持 Apple target 的 clang)"; exit 1; fi
	@echo "[*] Linux 交叉编译 (VARIANT=$(VARIANT))..."
	python3 tools/gen_web.py web/index.html $(WEB_HEADER)
	python3 tools/gen_web.py web/wechat-follow.png $(WECHAT_HEADER) kDHWeChatPNG
	$(CROSS_CC) $(ARCH_FLAGS) -isysroot $(IOS_SDK) -miphoneos-version-min=$(MIN_IOS) \
		-dynamiclib -install_name @executable_path/$(TARGET) \
		-ObjC -fobjc-arc -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
		-O2 $(INCLUDES) $(CAPSTONE_DEF) $(VERSION_DEF) -DDH_VARIANT=$(DH_VARIANT_NUM) $(FRAMEWORKS) \
		$(SRC) -o $(TARGET)
	@echo "✅ $(TARGET) (linux cross)"

# ---------- 3a) macOS 灰度测试 ----------
MAC_TARGET := decrypt_helper.mac.dylib
MAC_SDK    := $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null)
MAC_ARCH   := $(shell uname -m)
MAC_MIN    := 12.0
MAC_CFLAGS := -target $(MAC_ARCH)-apple-macos$(MAC_MIN) \
              -isysroot $(MAC_SDK) \
              -dynamiclib \
              -install_name @executable_path/$(MAC_TARGET) \
              -ObjC -fobjc-arc \
              -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
              -O0 -g \
              $(INCLUDES) \
              $(CAPSTONE_DEF) \
              $(VERSION_DEF) \
              -DDH_VARIANT=0 \
              -framework Foundation -framework CoreGraphics -framework Security

mac: $(WEB_ASSETS) $(MAC_TARGET)

$(MAC_TARGET): $(WEB_ASSETS) $(SRC) Makefile
	@if [ -z "$(MAC_SDK)" ]; then echo "❌ 没找到 macOS SDK"; exit 1; fi
	@echo "[*] macOS 编译 (arch=$(MAC_ARCH))..."
	$(CC) $(MAC_CFLAGS) $(SRC) -o $(MAC_TARGET)
	@echo "✅ macOS dylib: $(MAC_TARGET)"

# ---------- 3b) iOS Simulator ----------
SIM_TARGET := decrypt_helper.sim.dylib
SIM_SDK    := $(shell xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)
SIM_ARCH   := $(shell uname -m)
SIM_MIN    := 14.0
SIM_CFLAGS := -target $(SIM_ARCH)-apple-ios$(SIM_MIN)-simulator \
              -isysroot $(SIM_SDK) \
              -dynamiclib \
              -install_name @executable_path/$(SIM_TARGET) \
              -ObjC -fobjc-arc \
              -Wall -Wno-deprecated-declarations -Wno-nullability-completeness \
              -O0 -g \
              $(INCLUDES) \
              $(CAPSTONE_DEF) \
              $(VERSION_DEF) \
              $(FRAMEWORKS)

sim: $(WEB_ASSETS) $(SIM_TARGET)

$(SIM_TARGET): $(WEB_ASSETS) $(SRC) Makefile
	@if [ -z "$(SIM_SDK)" ]; then echo "❌ 没找到 iPhoneSimulator SDK"; exit 1; fi
	@echo "[*] iOS Simulator 编译 (arch=$(SIM_ARCH), min=$(SIM_MIN))..."
	$(CC) $(SIM_CFLAGS) $(SRC) -o $(SIM_TARGET)
	codesign -s - -f $(SIM_TARGET) 2>/dev/null || true
	@echo "✅ simulator dylib: $(SIM_TARGET)"

# ---------- 4) 发布产物: 带版本号的 dylib ----------
# 发布 Release 里的 dylib 资产时用:  make VARIANT=trollstore dist
# 文件名与 install_name(LC_ID) 都带版本; inject.sh 从文件名推导 LC_LOAD_DYLIB, 故注入仍自洽。
DIST_DYLIB := decrypt_helper-$(VERSION).dylib
dist: $(TARGET)
	cp $(TARGET) $(DIST_DYLIB)
	install_name_tool -id @executable_path/$(DIST_DYLIB) $(DIST_DYLIB)
	@echo "✅ 发布产物: $(DIST_DYLIB) (VARIANT=$(VARIANT))"

# ---------- 5) 越狱 deb 包 (rootless / roothide) ----------
# 引擎在本仓编译 → 落进 vendor/dylib/<variant>/ → 交给 build_deb.sh 打包。
# 每个 deb 包编自己的引擎变体, 架构也各按环境: rootless=arm64, roothide=arm64+arm64e。
# (1.27.5 及之前 roothide 包用的也是 rootless 变体引擎, 于是包内 version.plist 写
#  roothide 而引擎自报 rootless, 两者矛盾; 现已修正为各自对应的变体。)
.PHONY: stage-rootless stage-roothide

stage-rootless:
	@echo "[*] 编译引擎 (VARIANT=rootless, archs=arm64) → vendor/dylib/rootless"
	$(MAKE) -B VARIANT=rootless ARCHS=arm64 all
	mkdir -p vendor/dylib/rootless
	cp $(TARGET) vendor/dylib/rootless/$(TARGET)

stage-roothide:
	@echo "[*] 编译引擎 (VARIANT=roothide, archs=arm64 arm64e) → vendor/dylib/roothide"
	$(MAKE) -B VARIANT=roothide ARCHS="arm64 arm64e" all
	mkdir -p vendor/dylib/roothide
	cp $(TARGET) vendor/dylib/roothide/$(TARGET)

deb-rootless: stage-rootless
	@chmod +x build_deb.sh
	./build_deb.sh rootless

deb-roothide: stage-roothide
	@chmod +x build_deb.sh
	./build_deb.sh roothide

deb:
	$(MAKE) deb-rootless
	$(MAKE) deb-roothide

# 仿真回归测试：在 macOS 上把 daemon 跑成真机布局，用线上 release 走完整更新链路
# 测试需要一个「旧引擎」作替身，所以先 stage 一份 roothide 引擎（该目录不入版本库）
test-updater: stage-roothide
	@chmod +x tests/updater_sim_test.sh
	./tests/updater_sim_test.sh

clean:
	rm -f $(TARGET) $(MAC_TARGET) $(SIM_TARGET) decrypt_helper-*.dylib
	rm -f $(WEB_HEADER) $(WECHAT_HEADER)
	rm -f vendor/dylib/rootless/$(TARGET) vendor/dylib/roothide/$(TARGET)
	rm -rf build/

.PHONY: all linux mac sim dist clean deb deb-rootless deb-roothide test-updater
