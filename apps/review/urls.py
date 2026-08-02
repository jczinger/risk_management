"""Review queue URLs."""

from django.urls import path

from . import views

app_name = "review"

urlpatterns = [
    path("", views.queue, name="queue"),
    path("<int:pk>/affirm/", views.item_affirm, name="affirm"),
    path("<int:pk>/send-back/", views.item_send_back, name="send_back"),
]
