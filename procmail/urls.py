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
from django.conf.urls import patterns, url
from django.contrib.auth.decorators import login_required

import views

urlpatterns = patterns(
    '',
    url(r'^$', views.index, name="index"),
    url(r'^(?P<id>([0-9.]+))$', views.index, name="index"),
    url(r'^download$', views.download, name="download"),
    url(r'^delete/(?P<id>([0-9.]+))/(?P<view_name>([^/]+))', views.delete, name="delete"),
    url(r'^edit/(?P<id>([0-9.]*))', views.edit, name="edit"),
    url(r'^edit_simple/(?P<id>([0-9.]*))', views.edit_simple, name="edit_simple"),
    url(
        r'^move/(?P<old_id>([0-9.]+))/(?P<new_id>([0-9.]+))/(?P<curr_id>([0-9.]*))',
        views.move,
        name="move"
    ),
    url(r'^up/(?P<id>([0-9.]+))/(?P<cur_id>([0-9.]*))', views.up, name="up"),
    url(r'^down/(?P<id>([0-9.]+))/(?P<cur_id>([0-9.]*))', views.down, name="down"),
    url(
        r'^create/(?P<id>([0-9.]*))',
        login_required(views.CreateStatement.as_view()),
        name="create"
    ),
    url(r'^reverse$', views.reverse_view, name="reverse"),
)
