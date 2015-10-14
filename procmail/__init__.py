# ⁻*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015 Valentin Samir

from django.conf import settings
import collections

_DEFAULTS = {
    'PROCMAIL_INPLACE': True,
    'PROCMAIL_DEBUG_DIR': None,
    'PROCMAIL_OR_SCORE': 4294910507,
    'PROCMAIL_FALLBACK_ENCODING': 'ISO-8859-15',  # use a single-byte encodings
    'PROCMAIL_DEFAULT_ENCODING': 'utf-8',
    'PROCMAIL_DEFAULT_PROCMAILRC': (
        "#title:Preliminaries\n" +
        "SHELL=/bin/sh MAILDIR=${HOME}/Mail/ LOGFILE=${MAILDIR}/procmail.log " +
        'LOG="--- Logging for ${LOGNAME}, " FORMAIL=/usr/bin/formail\n'
    ),
    'PROCMAIL_VENDOR_CSS': {
        'bootstrap': "//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css",
        'font-awesome': "//maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css",
    },
    'PRCOMAIL_VENDOR_JAVASCRIPT': collections.OrderedDict([
        ('jquery', "//code.jquery.com/jquery-1.11.3.min.js"),
        ('jquery-ui', "//code.jquery.com/ui/1.11.4/jquery-ui.js"),
        ('sortable', "//cdn.jsdelivr.net/sortable/latest/Sortable.min.js"),
        ('bootstrap', "//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"),
    ]),
}

for key, value in list(_DEFAULTS.items()):
    try:
        getattr(settings, key)
    except AttributeError:
        setattr(settings, key, value)
    # Suppress errors from DJANGO_SETTINGS_MODULE not being set
    except ImportError:
        pass
