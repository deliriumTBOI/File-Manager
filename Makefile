# Makefile для программы мониторинга файлов
CC = gcc
CFLAGS_DEBUG = -Wall -Wextra -pedantic -g -pthread -std=c99 -MMD -MP
CFLAGS_RELEASE = -Wall -Wextra -pedantic -O2 -pthread -std=c99 -MMD -MP
CFLAGS = $(CFLAGS_RELEASE)
LDFLAGS = -lcrypto -lssl

# Определение директорий
SRC_DIR = src
OBJ_DIR = build
BIN_DIR = bin

# Целевой файл
TARGET = $(BIN_DIR)/file_monitor
CONFIG = $(SRC_DIR)/file_monitor.conf

# Исходные файлы
SRC = $(SRC_DIR)/file_monitor.c
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

# Зависимости
DEP = $(OBJ:.o=.d)

.PHONY: all clean config install help debug release run memcheck

all: $(TARGET)

# Создание необходимых директорий
$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

# Компиляция программы
$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

# Компиляция объектных файлов
$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Создание конфигурационного файла
config:
	@if [ ! -f $(CONFIG) ]; then \
		echo "# Файл конфигурации для программы мониторинга файлов" > $(CONFIG); \
		echo "# Интервал проверки в секундах" >> $(CONFIG); \
		echo "check_interval = 5" >> $(CONFIG); \
		echo "# Количество потоков для мониторинга" >> $(CONFIG); \
		echo "thread_count = 4" >> $(CONFIG); \
		echo "# Использовать inotify для отслеживания изменений (1 - да, 0 - нет)" >> $(CONFIG); \
		echo "use_inotify = 1" >> $(CONFIG); \
		echo "# Рекурсивное сканирование директорий (1 - да, 0 - нет)" >> $(CONFIG); \
		echo "recursive_scan = 1" >> $(CONFIG); \
		echo "# Использовать syslog для журналирования (1 - да, 0 - нет)" >> $(CONFIG); \
		echo "use_syslog = 0" >> $(CONFIG); \
		echo "# Уровень логирования (0 - INFO, 1 - WARNING, 2 - ERROR)" >> $(CONFIG); \
		echo "log_level = 0" >> $(CONFIG); \
		echo "# Файл для записи журнала (пустой - не использовать файл)" >> $(CONFIG); \
		echo "log_file = file_monitor.log" >> $(CONFIG); \
		echo "Создан файл конфигурации: $(CONFIG)"; \
	else \
		echo "Файл конфигурации уже существует: $(CONFIG)"; \
	fi

# Очистка проекта
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(SRC_DIR)/test?.txt $(SRC_DIR)/*.log $(SRC_DIR)/test_dir

# Установка программы
install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin
	install -d $(DESTDIR)/etc
	install -m 644 $(CONFIG) $(DESTDIR)/etc/file_monitor.conf || true

# Запуск memcheck для проверки памяти
memcheck: debug
	valgrind --leak-check=full \
	--show-leak-kinds=all \
	--track-origins=yes \
	./$(TARGET)

# Сборка отладочной версии
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: clean all

# Сборка релизной версии
release: CFLAGS = $(CFLAGS_RELEASE)
release: clean all

# Запуск программы
run: all
	$(TARGET) -c $(CONFIG)

# Вывод справки
help:
	@echo "Доступные цели:"
	@echo "  make       - сборка программы мониторинга файлов"
	@echo "  make config - создание файла конфигурации"
	@echo "  make clean - удаление скомпилированных файлов и тестовых данных"
	@echo "  make memcheck - запуск проверки памяти с valgrind"
	@echo "  make install - установка программы в систему"
	@echo "  make debug - сборка отладочной версии"
	@echo "  make release - сборка релизной версии"
	@echo "  make run - запуск программы"
	@echo "  make help  - вывод данной справки"

# Включаем файлы зависимостей
-include $(DEP)
