"""
URL configuration for gestion_lotes project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.urls import path


from lotes import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('registro/', views.registro, name='registro'),
    path('subir-plano/', views.subir_plano, name='subir_plano'),
    path('lotes/', views.listar_lotes, name='listar_lotes'),
    path('lote/<int:lote_id>/', views.detalle_lote, name='detalle_lote'),
    path('venta/', views.registrar_venta, name='registrar_venta'),
    path('log-actividad/', views.ver_log_actividad, name='ver_log_actividad'),
    path('agregar-lote/', views.agregar_lote, name='agregar_lote'),
    path('forgot-password/', views.send_reset_password_email, name='forgot_password'),
    path('reset-password/<uuid:token>/', views.reset_password, name='reset_password'),
]
