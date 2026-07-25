"""Department, role and volunteer URLs."""

from django.urls import path

from . import views

app_name = "org"

urlpatterns = [
    # Departments
    path("departments/", views.department_list, name="department_list"),
    path("departments/new/", views.department_create, name="department_create"),
    path("departments/<int:pk>/", views.department_detail, name="department_detail"),
    path("departments/<int:pk>/edit/", views.department_edit, name="department_edit"),
    # Roles
    path("roles/", views.role_list, name="role_list"),
    path("roles/new/", views.role_create, name="role_create"),
    path("roles/<int:pk>/", views.role_detail, name="role_detail"),
    path("roles/<int:pk>/edit/", views.role_edit, name="role_edit"),
    # Volunteers
    path("volunteers/", views.volunteer_list, name="volunteer_list"),
    path("volunteers/new/", views.volunteer_create, name="volunteer_create"),
    path("volunteers/<int:pk>/", views.volunteer_detail, name="volunteer_detail"),
    path("volunteers/<int:pk>/edit/", views.volunteer_edit, name="volunteer_edit"),
    path("volunteers/<int:pk>/deactivate/", views.volunteer_deactivate, name="volunteer_deactivate"),
    path("volunteers/<int:pk>/reactivate/", views.volunteer_reactivate, name="volunteer_reactivate"),
    path("volunteers/<int:pk>/resync/", views.volunteer_resync, name="volunteer_resync"),
    # Assignments
    path("volunteers/<int:pk>/assign/", views.assignment_create, name="assignment_create"),
    path("assignments/<int:pk>/end/", views.assignment_end, name="assignment_end"),
]
