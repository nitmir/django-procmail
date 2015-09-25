from django.conf.urls import patterns, url

import views

urlpatterns = patterns('',
    url(r'^$', views.index, name="index"),
    url(r'edit/(?P<id>([0-9.]+))', views.edit, name="edit"),
    url(r'up/(?P<id>([0-9.]+))/(?P<cur_id>([0-9.]*))', views.up, name="up"),
    url(r'down/(?P<id>([0-9.]+))/(?P<cur_id>([0-9.]*))', views.down, name="down"),
    url(r'create/(?P<id>([0-9.]+))', views.CreateStatement.as_view(), name="create"),
)
