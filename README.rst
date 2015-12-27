Django procmail
===============

.. image:: https://img.shields.io/pypi/v/django-procmail.svg
    :target: https://pypi.python.org/pypi/django-procmail

.. image:: https://img.shields.io/pypi/l/django-procmail.svg
    :target: https://www.gnu.org/licenses/gpl-3.0.html

Django procmail is a Django application allowing to edit procmail's procmailrc files.


Installation
------------

Install with pip::

    sudo pip install pyprocmail

or from source code::

    sudo make install


Quick start
-----------

1. Add ``procmail`` to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        'django.contrib.admin',
        ...,
        'procmail',
    )

   For internatinalization support, add ``django.middleware.locale.LocaleMiddleware``
   to your MIDDLEWARE_CLASSES setting like this::

    MIDDLEWARE_CLASSES = (
        ...
        'django.middleware.locale.LocaleMiddleware',
        ...
    )

2. Include the ``procmail`` URLconf in your project urls.py like this::

    urlpatterns = [
        url(r'^admin/', admin.site.urls),
        ...
        url(r'^procmail/', include('procmail.urls', namespace="procmail")),
    ]

3. Start the development server and visit http://127.0.0.1:8000/procmail/
   to edit your procmailrc.



Settings
--------

All settings are optional. Add them to ``settings.py`` to customize ``django-procmail``:

* ``PROCMAIL_INPLACE``: Should ``django-procmail`` try to edit procmailrc inplace ?
  The default is ``True``
* ``PROCMAIL_DEBUG_DIR``: When ``PROCMAIL_INPLACE`` is False, where do we copy procmailrc files for
  edition. The default is ``None``, no dir defined. The default will crash if ``PROCMAIL_INPLACE``
  is False.
* ``PROCMAIL_TEST_PROCMAILRC``: Path to a procmailrc file, used for every user when defined.
  It is here for testing purpose. The defaut is ``None``.
* ``PROCMAIL_FALLBACK_ENCODING``: Which encoding to use for reading procmailrc files when
  charset autodetection failed. The default is ``'ISO-8859-15'``. You should always use
  single-byte encodings of this parameter.
* ``PROCMAIL_DEFAULT_ENCODING``: Chich encoding to use for reading and writing procmailrc files.
  If read failed (bad charset), we try to autodetect the charset, is the autodetection failed, we
  fallback to ``PROCMAIL_FALLBACK_ENCODING``. The default is ``'utf-8'``.
* ``PROCMAIL_DEFAULT_PROCMAILRC``: The content of the created procmailrc file when the user do not
  already have a procmailrc file.
* ``PROCMAIL_VENDOR_CSS``: A dictionnary with two keys ``'bootstrap'`` and ``'font-awesome'``.
  The url to bootstrap3 and fontawesome CSS. The default are
  ``"//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css"`` and
  ``"//maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css"``.
* ``PRCOMAIL_VENDOR_JAVASCRIPT``: A ordered dictionnary with four keys ``'jquery'``, ``'jquery-ui'``,
  ``'sortable'``, ``'bootstrap'``. The default are respectively
  ``"//code.jquery.com/jquery-1.11.3.min.js"``, ``"//code.jquery.com/ui/1.11.4/jquery-ui.js"``,
  ``//cdn.jsdelivr.net/sortable/latest/Sortable.min.js"`` and
  ``"//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"``.
