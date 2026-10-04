# Makefile для ЛР4: единая точка входа для сборки, тестирования и анализа.
#
#   make build        - конфигурация и обычная сборка приложения и тестов;
#   make run          - сборка и запуск приложения на samples/records.txt;
#   make test         - только запуск ранее собранных тестов (без сборки);
#   make build-test   - сначала сборка, затем тестирование;
#   make static       - статический анализ cppcheck;
#   make asan         - сборка и тесты с AddressSanitizer и UndefinedBehaviorSanitizer;
#   make fuzz         - фаззинг AFL++ (только Linux, нужен afl-clang-fast++ и afl-fuzz);
#   make clean        - удалить каталоги сборки.
#
# Компилятор можно переопределить: make build CXX_COMPILER=g++ CC_COMPILER=gcc

CMAKE          ?= cmake
CC_COMPILER    ?= clang
CXX_COMPILER   ?= clang++
GENERATOR      ?= Ninja
BUILD_DIR      ?= build
BUILD_SAN_DIR  ?= build-asan
BUILD_FUZZ_DIR ?= build-afl
JOBS           ?= 4

ifeq ($(OS),Windows_NT)
EXE_SUFFIX := .exe
else
EXE_SUFFIX :=
endif

APP := $(BUILD_DIR)/credcheck$(EXE_SUFFIX)

.PHONY: build run test build-test static asan fuzz clean

build:
	$(CMAKE) -S . -B $(BUILD_DIR) -G $(GENERATOR) \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_COMPILER=$(CC_COMPILER) -DCMAKE_CXX_COMPILER=$(CXX_COMPILER)
	$(CMAKE) --build $(BUILD_DIR) --parallel $(JOBS)

run:
	$(MAKE) build
	$(APP) samples/records.txt

test:
	ctest --test-dir $(BUILD_DIR) --output-on-failure

build-test:
	$(MAKE) build
	$(MAKE) test

static:
	cppcheck --enable=warning,style,performance,portability --std=c++17 \
		--error-exitcode=1 --inline-suppr -I include --quiet src app

asan:
	$(CMAKE) -S . -B $(BUILD_SAN_DIR) -G $(GENERATOR) \
		-DLR4_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug \
		-DCMAKE_C_COMPILER=$(CC_COMPILER) -DCMAKE_CXX_COMPILER=$(CXX_COMPILER)
	$(CMAKE) --build $(BUILD_SAN_DIR) --parallel $(JOBS)
	ctest --test-dir $(BUILD_SAN_DIR) --output-on-failure

fuzz:
	$(CMAKE) -S . -B $(BUILD_FUZZ_DIR) -G $(GENERATOR) -DLR4_FUZZ=ON \
		-DCMAKE_C_COMPILER=afl-clang-fast -DCMAKE_CXX_COMPILER=afl-clang-fast++
	$(CMAKE) --build $(BUILD_FUZZ_DIR) --target fuzz_parse
	AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 timeout 60 afl-fuzz -i fuzz/seeds -o findings -- $(BUILD_FUZZ_DIR)/fuzz_parse; \
		status=$$?; if [ $$status -ne 0 ] && [ $$status -ne 124 ]; then exit $$status; fi

clean:
	rm -rf $(BUILD_DIR) $(BUILD_SAN_DIR) $(BUILD_FUZZ_DIR) findings
