"""Reporting and audit URLs."""

from django.urls import path

from . import views

app_name = "reporting"

urlpatterns = [
    path("compliance/", views.compliance_report, name="compliance"),
    path("volunteer/<int:pk>/file/", views.volunteer_file, name="volunteer_file"),
    path("audit/", views.audit_trail, name="audit_trail"),
    path("audit/<int:pk>/", views.audit_event_detail, name="audit_event_detail"),
    path("email-log/", views.email_log, name="email_log"),
]
