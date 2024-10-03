from rest_framework import serializers
from .models import LogActividad, Lote, Plano, Usuario, Venta

class UsuarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = ['id', 'username', 'nombre', 'email', 'rol', 'fecha_registro']
        
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

class PlanoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plano
        fields = ['nombre_plano', 'archivo_plano', 'subido_por']  # Incluye el campo subido_por si lo necesitas
        
class LoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lote
        fields = '__all__'  # Esto incluirá todos los campos del modelo Lote
        
class VentaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Venta
        fields = ['id', 'id_lote', 'id_comprador', 'precio_venta', 'fecha_venta', 'condiciones']
        
class LogActividadSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogActividad
        fields = ['id_usuario', 'accion', 'fecha']
