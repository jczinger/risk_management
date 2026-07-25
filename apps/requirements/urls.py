"""Requirement engine URLs.

Note what is absent: there is no URL that lifts a permanent disqualification. That is
the point (Build Spec §4.3).
"""

from django.urls import path

from . import views

app_name = "requirements"

urlpatterns = [
    # The church's requirement list
    path("", views.definition_list, name="definition_list"),
    path("new/", views.definition_create, name="definition_create"),
    path("seed/", views.definition_seed, name="definition_seed"),
    path("<int:pk>/", views.definition_detail, name="definition_detail"),
    path("<int:pk>/edit/", views.definition_edit, name="definition_edit"),
    path("<int:pk>/toggle/", views.definition_toggle_active, name="definition_toggle_active"),
    # One volunteer's progress
    path("instances/<int:pk>/", views.instance_detail, name="instance_detail"),
    path("instances/<int:pk>/complete/", views.instance_complete, name="instance_complete"),
    path("instances/<int:pk>/start/", views.instance_start, name="instance_start"),
    path("instances/<int:pk>/waive/", views.instance_waive, name="instance_waive"),
    # Criminal record checks
    path("crc/volunteer/<int:volunteer_pk>/new/", views.crc_record_create, name="crc_create"),
    path("crc/<int:pk>/", views.crc_detail, name="crc_detail"),
    path("crc/<int:pk>/convictions/add/", views.crc_conviction_add, name="crc_conviction_add"),
    path("crc/<int:pk>/override/", views.crc_override, name="crc_override"),
    path("crc/<int:pk>/resolve/", views.crc_resolve_not_clear, name="crc_resolve"),
]
