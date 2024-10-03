from urllib.request import Request
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth.hashers import make_password
from .models import LogActividad, Usuario, Lote, Venta
from .serializers import LogActividadSerializer, LoteSerializer, PlanoSerializer, UsuarioSerializer, VentaSerializer
from django.db import IntegrityError

#import email
from django.core.mail import send_mail
from django.shortcuts import render
from django.http import JsonResponse
from django.urls import reverse
from .models import PasswordResetToken
from django.conf import settings
from django.contrib.auth.models import User

@api_view(['POST'])
def registro(request):
    data = request.data
    
    # Validación de los campos
    if 'username' not in data or 'password' not in data or 'email' not in data or 'rol' not in data:
        return Response({'error': 'Todos los campos son requeridos: username, email, password, rol'}, status=status.HTTP_400_BAD_REQUEST)

    # Cifrar la contraseña
    password_hashed = make_password(data['password'])
    
    # Crear el usuario
    try:
        usuario = Usuario.objects.create(
            username=data['username'],  # Aquí usamos 'username' como identificador
            nombre=data['nombre'],  # Nombre completo del usuario
            email=data['email'],
            password=password_hashed,
            rol=data.get('rol', 'comprador')
        )
    except IntegrityError:
        return Response({'error': 'El username o el email ya están en uso'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Agregar registro al log de actividades
    LogActividad.objects.create(
        id_usuario=usuario,
        accion='Usuario registrado',
    )
    
    # Serializar el usuario
    serializer = UsuarioSerializer(usuario)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['POST'])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    usuario = authenticate(request, username=username, password=password)

    if usuario is not None:
        # Aquí puedes generar un token o simplemente confirmar que el login es exitoso
        return Response({'detail': 'Inicio de sesión exitoso', 'username': usuario.username}, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'No active account found with the given credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def subir_plano(request):
    if request.method == 'POST':
        serializer = PlanoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(subido_por=request.user)  # Guardamos el plano con el usuario que lo subió
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
def agregar_lote(request):
    serializer = LoteSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def listar_lotes(request):
    estado = request.query_params.get('estado', None)  # Permite filtrar por estado
    if estado:
        lotes = Lote.objects.filter(estado=estado)
    else:
        lotes = Lote.objects.all()
    
    serializer = LoteSerializer(lotes, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def detalle_lote(request, lote_id):
    try:
        lote = Lote.objects.get(id=lote_id)
    except Lote.DoesNotExist:
        return Response({'error': 'Lote no encontrado'}, status=status.HTTP_404_NOT_FOUND)

    serializer = LoteSerializer(lote)
    return Response(serializer.data)

@api_view(['POST'])
def registrar_venta(request):
    try:
        lote = Lote.objects.get(id=request.data['id_lote'])
        comprador = Usuario.objects.get(id=request.data['id_comprador'])

        venta = Venta.objects.create(
            id_lote=lote,
            id_comprador=comprador,
            precio_venta=request.data['precio_venta'],
            condiciones=request.data.get('condiciones', '')
        )

        # Actualizar estado del lote a vendido
        lote.estado = 'vendido'
        lote.save()

        serializer = VentaSerializer(venta)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    except Lote.DoesNotExist:
        return Response({'error': 'Lote no encontrado'}, status=status.HTTP_404_NOT_FOUND)
    except Usuario.DoesNotExist:
        return Response({'error': 'Comprador no encontrado'}, status=status.HTTP_404_NOT_FOUND)  # Agregar este return

@api_view(['GET'])
def ver_log_actividad(request):
    log = LogActividad.objects.all()
    serializer = LogActividadSerializer(log, many=True)
    return Response(serializer.data)


def send_reset_password_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return JsonResponse({'error': 'Email not found'}, status=404)

        # Crear un token de recuperación de contraseña
        token = PasswordResetToken.objects.create(user=user)

        # Generar el enlace de restablecimiento de contraseña
        reset_link = request.build_absolute_uri(
            reverse('reset_password', kwargs={'token': token.token})
        )

        # Enviar el correo
        send_mail(
            'Reset your password',
            f'Hi {user.username}, use this link to reset your password: {reset_link}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        return JsonResponse({'message': 'Password reset email sent'})
    


def reset_password(request, token):
    try:
        reset_token = PasswordResetToken.objects.get(token=token, is_used=False)
    except PasswordResetToken.DoesNotExist:
        return JsonResponse({'error': 'Invalid or expired token'}, status=400)

    if not reset_token.is_token_valid():
        return JsonResponse({'error': 'Token expired'}, status=400)

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            return JsonResponse({'error': 'Passwords do not match'}, status=400)

        # Cambiar la contraseña del usuario
        reset_token.user.password = make_password(new_password)
        reset_token.user.save()

        # Marcar el token como usado
        reset_token.is_used = True
        reset_token.save()

        return JsonResponse({'message': 'Password reset successful'})

