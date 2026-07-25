"""Super-admin console URLs (public schema only)."""

from django.urls import path

from . import views

app_name = "tenants"

urlpatterns = [
    path("", views.church_list, name="church_list"),
    path("churches/new/", views.church_create, name="church_create"),
    path("churches/<int:pk>/", views.church_detail, name="church_detail"),
    path("churches/<int:pk>/key/", views.church_key_shown, name="church_key_shown"),
    path("churches/<int:pk>/settings/", views.church_settings, name="church_settings"),
    path("churches/<int:pk>/restore-key/", views.church_restore_key, name="church_restore_key"),
]
