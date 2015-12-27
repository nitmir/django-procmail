.PHONY: clean build install dist test_venv
VERSION=`python setup.py -V`

build:
	python setup.py build

install: dist
	pip install pyprocmail -U --force-reinstall --no-deps -f ./dist/pyprocmail-${VERSION}.tar.gz
uninstall:
	pip uninstall pyprocmail || true

clean_pyc:
	find ./ -name '*.pyc' -delete
	find ./ -name __pycache__ -delete
clean_build:
	rm -rf build django_procmail.egg-info dist
clean_test_venv:
	rm -rf test_venv
clean: clean_pyc clean_build
clean_all: clean_pyc clean_build clean_test_venv

dist:
	python setup.py sdist

test_venv: dist
	mkdir -p test_venv
	virtualenv test_venv
	test_venv/bin/pip install -U django-procmail -f ./dist/django-procmail-${VERSION}.tar.gz

test_venv/project:
	mkdir -p test_venv/project
	test_venv/bin/django-admin startproject project test_venv/project
	sed -i "s/'django.contrib.staticfiles',/'django.contrib.staticfiles',\n    'procmail',/" test_venv/project/project/settings.py
	sed -i "s/'django.middleware.clickjacking.XFrameOptionsMiddleware',/'django.middleware.clickjacking.XFrameOptionsMiddleware',\n    'django.middleware.locale.LocaleMiddleware',/" test_venv/project/project/settings.py
	sed -i 's/from django.conf.urls import url/from django.conf.urls import url, include/' test_venv/project/project/urls.py
	sed -i "s@url(r'^admin/', admin.site.urls),@url(r'^admin/', admin.site.urls),\n    url(r'^', include('procmail.urls', namespace='procmail')),@" test_venv/project/project/urls.py
	test_venv/bin/python test_venv/project/manage.py migrate
	test_venv/bin/python test_venv/project/manage.py createsuperuser

run_test_server: test_venv test_venv/project
	test_venv/bin/python test_venv/project/manage.py runserver
