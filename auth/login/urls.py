from django.urls import path
from . import views
urlpatterns=[
    path("User/",views.UserListCreate.as_view(),name="User-view-create"),
    path("login/",views.LoginView.as_view(), name="login"),
    path("register/", views.RegisterView.as_view(), name="register"),
]