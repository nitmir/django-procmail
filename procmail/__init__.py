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


_DEFAULTS = {
    'PROCMAIL_INPLACE': True,
    'PROCMAIL_DEBUG_DIR': None,
    'PROCMAIL_OR_SCORE': 4294910507,
    'PROCMAIL_FALLBACK_ENCODING': 'ISO-8859-15',  # use a single-byte encodings
    'PROCMAIL_DEFAULT_ENCODING': 'utf-8',
}

for key, value in list(_DEFAULTS.items()):
    try:
        getattr(settings, key)
    except AttributeError:
        setattr(settings, key, value)
    # Suppress errors from DJANGO_SETTINGS_MODULE not being set
    except ImportError:
        pass
