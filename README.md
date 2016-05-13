Пример ЭЦП XML-файла для ГИС ЖКХ
================================

Этот пример демонстрирует реализацию ЭЦП для ГИС ЖКХ на Python и OpenSSL.

1. Настройка окружения
=======================

1) Установить openssl версии старше 1.0
2) Для поддержки ГОСТ добавить в конфигурационный файл:

UNIX
----
	openssl_conf = openssl_def

	<...оставшееся содержимое файла...>

	[openssl_def]
	engines = engine_section

	[engine_section]
	gost = gost_section

	[gost_section]
	soft_load=1
	default_algorithms = ALL 


WINDOWS:
--------
	openssl_conf = openssl_def

	<...оставшееся содержимое файла...>

	[openssl_def]
	engines = engine_section

	[engine_section]
	gost = gost_section

	[gost_section]
	engine_id = gost
	dynamic_path = ./gost.dll
	default_algorithms = ALL


Добавить в переменные окружения путь к конфигу OpenSSL:

	OPENSSL_CONF=c:\OpenSSL-Win32\bin\openssl.cfg


3) Установить зависимости:
	pip install -r requirements.txt	

2. Использование
================

	python sign.py cert.key in.xml f9f93de1-05b6-11e5-b4ae-1c6f65dfe2b1 > out.xml
	