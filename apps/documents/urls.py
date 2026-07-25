"""Document URLs."""

from django.urls import path

from . import views

app_name = "documents"

urlpatterns = [
    path("", views.document_list, name="list"),
    path("volunteer/<int:volunteer_pk>/add/", views.document_create, name="create"),
    path("<int:pk>/", views.document_detail, name="detail"),
    path("<int:pk>/file/", views.document_download, name="download"),
]
