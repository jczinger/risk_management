"""
Account URLs.

Included by both URLconfs: the platform super-admin signs in through the same views as
a church's screening admins, just in the public schema.
"""

from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    # Sign in / out
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    # Passkey ceremonies (fetch endpoints)
    path("webauthn/auth/begin/", views.webauthn_authenticate_begin, name="webauthn_auth_begin"),
    path("webauthn/auth/finish/", views.webauthn_authenticate_finish, name="webauthn_auth_finish"),
    path("webauthn/register/begin/", views.webauthn_register_begin, name="webauthn_register_begin"),
    path(
        "webauthn/register/finish/",
        views.webauthn_register_finish,
        name="webauthn_register_finish",
    ),
    path("passkeys/<int:pk>/remove/", views.passkey_remove, name="passkey_remove"),
    path("passkey-required/", views.passkey_required, name="passkey_required"),
    # Sign-in links
    path("recover/", views.recover_request, name="recover"),
    path("link/<str:payload>/", views.link_consume, name="link_consume"),
    # Own account
    path("security/", views.security, name="security"),
    path("profile/", views.profile, name="profile"),
    # This church's other admins
    path("administrators/", views.admin_list, name="admin_list"),
    path("administrators/add/", views.admin_invite, name="admin_invite"),
    path(
        "administrators/<int:pk>/toggle/",
        views.admin_toggle_active,
        name="admin_toggle_active",
    ),
]
