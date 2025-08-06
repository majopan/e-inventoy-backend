from rest_framework import serializers # type: ignore
from django.contrib.auth import authenticate # type: ignore
from django.contrib.auth.hashers import make_password # type: ignore
from django.utils.translation import gettext_lazy as _ # type: ignore
from django.db import transaction # type: ignore
from .models import RolUser, Sede, Dispositivo, Servicios, Posicion, Historial, Movimiento, UsuarioExterno, AsignacionDispositivo, RegistroMovimientoDispositivo
from .models import Piso, SubPiso
class RolUserSerializer(serializers.ModelSerializer):
    sedes = serializers.PrimaryKeyRelatedField(queryset=Sede.objects.all(), many=True, required=False)
    password = serializers.CharField(write_only=True, required=False, min_length=8)

    class Meta:
        model = RolUser
        fields = ['id', 'username', 'nombre', 'email', 'rol', 'celular', 'documento', 'sedes', 'password', 'is_active', 'last_activity']

    def validate_email(self, value):
        return value.lower().strip()

    def validate_celular(self, value):
        import re
        if value and not re.match(r'^\+?\d{7,15}$', value):
            raise serializers.ValidationError(
                "El número de celular debe ser un número válido con 7 a 15 dígitos, y puede incluir un signo '+' al principio."
            )
        return value

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = super().create(validated_data)
        if password:
            user.password = make_password(password)
            user.save()
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            user.password = make_password(password)
            user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError(_('Credenciales inválidas'))
        if not user.is_active:
            raise serializers.ValidationError(_('La cuenta está inactiva.'))
        data['user'] = user
        return data

class DispositivoSerializer(serializers.ModelSerializer):
    sede = serializers.PrimaryKeyRelatedField(
        queryset=Sede.objects.all(), 
        required=False,
        allow_null=True
    )
    nombre_sede = serializers.SerializerMethodField()
    posicion = serializers.PrimaryKeyRelatedField(
        queryset=Posicion.objects.all(), 
        required=False,
        allow_null=True
    )
    posicion_nombre = serializers.SerializerMethodField()
    servicio_nombre = serializers.SerializerMethodField()
    codigo_analitico = serializers.SerializerMethodField()
    tipo_display = serializers.CharField(source='get_tipo_display', read_only=True)
    estado_display = serializers.CharField(source='get_estado_display', read_only=True)
    marca_display = serializers.CharField(source='get_marca_display', read_only=True)
    sistema_operativo_display = serializers.CharField(source='get_sistema_operativo_display', read_only=True)
    is_operativo = serializers.SerializerMethodField()

    TIPOS_CON_REQUISITOS = ['COMPUTADOR', 'PORTATIL', 'DESKTOP', 'TODO_EN_UNO']
    ESTADOS_INVALIDOS = ['MALO', 'PERDIDO_ROBADO', 'PENDIENTE_BAJA']

    class Meta:
        model = Dispositivo
        fields = '__all__'
        extra_kwargs = {
            'serial': {'required': True, 'allow_blank': False},
            'modelo': {'required': True, 'allow_blank': False},
            'tipo': {'required': True},
            'marca': {'required': True},
            'estado': {'required': True},
            'placa_cu': {'allow_blank': True},
            'observaciones': {'allow_blank': True, 'required': False}
        }
    def get_posicion_nombre(self, obj):
        return obj.posicion.nombre if obj.posicion else None
    
    def get_servicio_nombre(self, obj):
        return obj.posicion.servicio.nombre if obj.posicion and obj.posicion.servicio else None
    
    def get_codigo_analitico(self, obj):
        return obj.posicion.servicio.codigo_analitico if obj.posicion and obj.posicion.servicio else None
    
    def get_nombre_sede(self, obj):
        return obj.sede.nombre if obj.sede else None

    def get_is_operativo(self, obj):
        return obj.is_operativo()

    def validate(self, data):
        request = self.context.get('request')
        instance = getattr(self, 'instance', None)
        
        # Validaciones básicas
        if request and request.method == 'POST' and 'serial' in data:
            if Dispositivo.objects.filter(serial=data['serial']).exists():
                raise serializers.ValidationError({'serial': 'Ya existe un dispositivo con este serial'})

        if 'placa_cu' in data and data['placa_cu']:
            queryset = Dispositivo.objects.filter(placa_cu=data['placa_cu'])
            if instance:
                queryset = queryset.exclude(pk=instance.pk)
            if queryset.exists():
                raise serializers.ValidationError({'placa_cu': 'Ya existe un dispositivo con esta placa CU'})

        # Validaciones de posición y sede
        posicion = data.get('posicion', instance.posicion if instance else None)
        sede = data.get('sede', instance.sede if instance else None)
        
        if posicion and not sede:
            raise serializers.ValidationError({'sede': 'Debe especificar una sede si asigna una posición'})
            
        if posicion and sede and posicion.sede != sede:
            raise serializers.ValidationError({
                'posicion': f'La posición seleccionada pertenece a la sede {posicion.sede.nombre}, no coincide con la sede del dispositivo {sede.nombre}'
            })

        # Validar límite de dispositivos en posición
        if posicion:
            dispositivos_count = posicion.dispositivos_relacionados.count()
            if not instance or (instance and instance.posicion != posicion):
                if dispositivos_count >= Posicion.MAX_DISPOSITIVOS:
                    raise serializers.ValidationError({
                        'posicion': f'Esta posición ya tiene el máximo de {Posicion.MAX_DISPOSITIVOS} dispositivos'
                    })

        # Validaciones específicas del dispositivo
        dispositivo_tipo = data.get('tipo', getattr(instance, 'tipo', None))
        if dispositivo_tipo in self.TIPOS_CON_REQUISITOS:
            required_fields = {
                'capacidad_memoria_ram': 'Capacidad de RAM requerida para este dispositivo',
                'sistema_operativo': 'Sistema operativo requerido para este dispositivo',
                'procesador': 'Procesador requerido para este dispositivo'
            }
            for field, error_msg in required_fields.items():
                if not data.get(field) and not getattr(instance, field, None):
                    raise serializers.ValidationError({field: error_msg})

        if data.get('estado') in self.ESTADOS_INVALIDOS:
            if data.get('estado_uso') and data.get('estado_uso') != 'INHABILITADO':
                raise serializers.ValidationError({
                    'estado_uso': 'El estado de uso debe ser INHABILITADO cuando el estado del dispositivo es inválido.'
                })
            data['estado_uso'] = 'INHABILITADO'

        return data

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user if request else None
        
        try:
            with transaction.atomic():
                posicion = validated_data.get('posicion')
                if posicion and posicion.dispositivos_relacionados.count() >= Posicion.MAX_DISPOSITIVOS:
                    raise serializers.ValidationError({
                        'posicion': f'No se puede agregar más dispositivos. Límite de {Posicion.MAX_DISPOSITIVOS} alcanzado'
                    })
                
                if posicion:
                    validated_data['piso'] = posicion.piso
                
                dispositivo = super().create(validated_data)
                
                if posicion:
                    posicion.dispositivos.add(dispositivo)
                    Movimiento.objects.create(
                        dispositivo=dispositivo,
                        posicion_origen=None,
                        posicion_destino=posicion,
                        encargado=user,
                        sede=dispositivo.sede,
                        observacion="Creación de dispositivo con posición"
                    )
                
                return dispositivo
        except Exception as e:
            raise serializers.ValidationError({'non_field_errors': f'Error al crear el dispositivo: {str(e)}'})

    def update(self, instance, validated_data):
        request = self.context.get('request')
        user = request.user if request else None
        posicion_anterior = instance.posicion
        nueva_posicion = validated_data.get('posicion')
        
        try:
            with transaction.atomic():
                # 1. Verificar coherencia de sedes si hay nueva posición
                if nueva_posicion and 'sede' not in validated_data:
                    if instance.sede != nueva_posicion.sede:
                        raise serializers.ValidationError({
                            'posicion': f'La posición pertenece a otra sede ({nueva_posicion.sede.nombre}). Actualice también la sede del dispositivo.'
                        })
                
                # 2. Verificar límite en nueva posición
                if nueva_posicion and nueva_posicion != posicion_anterior:
                    if nueva_posicion.dispositivos.count() >= Posicion.MAX_DISPOSITIVOS:
                        raise serializers.ValidationError({
                            'posicion': f'No se puede mover. La posición ya tiene {Posicion.MAX_DISPOSITIVOS} dispositivos.'
                        })
                
                # 3. Remover de TODAS las posiciones anteriores (por si estaba en múltiples)
                if 'posicion' in validated_data:
                    for pos in instance.posiciones.all():
                        pos.dispositivos.remove(instance)
                
                # 4. Actualizar campos normales
                for attr, value in validated_data.items():
                    setattr(instance, attr, value)
                
                # 5. Actualizar piso según nueva posición
                if 'posicion' in validated_data:
                    instance.piso = nueva_posicion.piso if nueva_posicion else None
                
                instance.save()
                
                # 6. Agregar a nueva posición si existe
                if nueva_posicion:
                    nueva_posicion.dispositivos.add(instance)
                
                # 7. Registrar movimiento con observación detallada
                if posicion_anterior != nueva_posicion:
                    observacion = (
                        f"Reasignación completa de posición | "
                        f"Anterior: {posicion_anterior.nombre if posicion_anterior else 'Ninguna'} ({posicion_anterior.sede.nombre if posicion_anterior else 'N/A'}) | "
                        f"Nueva: {nueva_posicion.nombre if nueva_posicion else 'Ninguna'} ({nueva_posicion.sede.nombre if nueva_posicion else 'N/A'}) | "
                        f"Realizado por: {user.username if user else 'Sistema'}"
                    )
                    
                    Movimiento.objects.create(
                        dispositivo=instance,
                        posicion_origen=posicion_anterior,
                        posicion_destino=nueva_posicion,
                        encargado=user,
                        sede=instance.sede,
                        observacion=observacion
                    )
                
                return instance
                
        except Exception as e:
            raise serializers.ValidationError({
                'non_field_errors': f'Error crítico al actualizar: {str(e)}'
            })

class SedeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sede
        fields = ['id', 'nombre', 'ciudad', 'direccion']

class ServiciosSerializer(serializers.ModelSerializer):
    sedes = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Sede.objects.all(),
        required=False
    )

    class Meta:
        model = Servicios
        fields = ['id', 'nombre', 'codigo_analitico', 'sedes', 'color']

from rest_framework import serializers
from django.db import transaction
from .models import Posicion, Dispositivo, Servicios
from django.contrib.auth import get_user_model
import logging
import traceback

logger = logging.getLogger(__name__)
User = get_user_model()

class PosicionSerializer(serializers.ModelSerializer):
    dispositivos = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Dispositivo.objects.all(),
        required=False
    )
    sede_nombre = serializers.CharField(source='sede.nombre', read_only=True)
    cantidad_dispositivos = serializers.SerializerMethodField()
    servicio = serializers.SerializerMethodField()

    servicio_id = serializers.IntegerField(
        write_only=True,
        required=False,
        allow_null=True,
        source='servicio.id'
    )
    
    class Meta:
        model = Posicion
        fields = [
            'id', 'nombre', 'tipo', 'estado', 'detalles', 'fila', 'columna',
            'color', 'colorFuente', 'colorOriginal', 'borde', 'bordeDoble',
            'bordeDetalle', 'piso', 'servicio', 'servicio_id', 'dispositivos',
            'mergedCells', 'sede_nombre', 'cantidad_dispositivos'
        ]
        extra_kwargs = {
            'sede': {'required': False},
            'servicio': {'required': False, 'allow_null': True}
        }

    def get_servicio(self, obj):
        """Obtiene los datos del servicio si existe"""
        if obj.servicio:
            return {
                'id': obj.servicio.id,
                'nombre': obj.servicio.nombre,
                'color': obj.servicio.color,
                'colorFuente': getattr(obj.servicio, 'colorFuente', '#000000')
            }
        return None

    def get_authenticated_user(self):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            return request.user if not request.user.is_anonymous else None
        return None

    def get_cantidad_dispositivos(self, obj):
        return obj.dispositivos.count()

    def validate(self, data):
        if 'fila' in data and data['fila'] < 1:
            raise serializers.ValidationError({
                'fila': 'La fila debe ser un número positivo.'
            })

        if 'columna' in data and not str(data['columna']).isalpha():
            raise serializers.ValidationError({
                'columna': 'La columna debe contener solo letras.'
            })

        dispositivos_data = data.get('dispositivos', [])
        if dispositivos_data and len(dispositivos_data) > Posicion.MAX_DISPOSITIVOS:
            raise serializers.ValidationError({
                'dispositivos': f'Máximo {Posicion.MAX_DISPOSITIVOS} dispositivos permitidos por posición'
            })

        if 'piso' not in data and (not self.instance or not self.instance.piso):
            raise serializers.ValidationError({
                'piso': 'Debe especificar un piso para la posición.'
            })

        return data

    def create(self, validated_data):
        user = self.get_authenticated_user()
        dispositivos_data = validated_data.pop('dispositivos', [])
        servicio_data = validated_data.pop('servicio', None)

        try:
            with transaction.atomic():
                instance = super().create(validated_data)

                if dispositivos_data:
                    instance.dispositivos.set(dispositivos_data)
                    for dispositivo in dispositivos_data:
                        dispositivo.posicion = instance
                        dispositivo.piso = instance.piso
                        dispositivo.save()

                logger.info(f"Posición {instance.id} creada exitosamente por el usuario {user}")
                return instance

        except Exception as e:
            logger.error(f"Error al crear posición: {str(e)}")
            print(traceback.format_exc())
            raise serializers.ValidationError({
                'non_field_errors': f'Error al crear posición: {str(e)}'
            })

    def update(self, instance, validated_data):
        user = self.get_authenticated_user()
        dispositivos_data = validated_data.pop('dispositivos', None)
        servicio_data = validated_data.pop('servicio', None)

        try:
            with transaction.atomic():
                # Asignar servicio si fue enviado
                if servicio_data is not None:
                    servicio_id = servicio_data.get('id')
                    instance.servicio_id = servicio_id

                # Actualizar campos normales
                for attr, value in validated_data.items():
                    setattr(instance, attr, value)
                instance.save()

                if dispositivos_data is not None:
                    # Puede ser [] para quitar todos
                    instance.dispositivos.set(dispositivos_data)

                    for dispositivo in dispositivos_data:
                        dispositivo.posicion = instance
                        dispositivo.piso = instance.piso
                        dispositivo.save()

                logger.info(f"Posición {instance.id} actualizada por el usuario {user}")
                return instance

        except Exception as e:
            logger.error(f"Error al actualizar posición {instance.id}: {str(e)}")
            print(traceback.format_exc())
            raise serializers.ValidationError({
                'non_field_errors': f'Error al actualizar posición: {str(e)}'
            })


class HistorialSerializer(serializers.ModelSerializer):
    dispositivo = DispositivoSerializer(read_only=True)
    usuario = RolUserSerializer(read_only=True)
    tipo_cambio_display = serializers.CharField(source='get_tipo_cambio_display', read_only=True)
    fecha_formateada = serializers.SerializerMethodField()
    
    class Meta:
        model = Historial
        fields = '__all__'
    
    def get_fecha_formateada(self, obj):
        return obj.fecha_modificacion.strftime("%d/%m/%Y %H:%M")

from rest_framework import serializers # type: ignore
from .models import Movimiento, Dispositivo, Posicion, RolUser

class MovimientoSerializer(serializers.ModelSerializer):
    dispositivo_info = serializers.SerializerMethodField()
    posicion_origen_info = serializers.SerializerMethodField()
    posicion_destino_info = serializers.SerializerMethodField()
    encargado_info = serializers.SerializerMethodField()
    sede_info = serializers.SerializerMethodField()

    class Meta:
        model = Movimiento
        fields ='__all__'
        extra_kwargs = {
            'fecha_movimiento': {'read_only': True},
            'encargado': {'required': False}
        }

    def get_dispositivo_info(self, obj):
        if obj.dispositivo:
            return {
                'id': obj.dispositivo.id,
                'serial': obj.dispositivo.serial,
                'modelo': obj.dispositivo.modelo,
                'tipo': obj.dispositivo.get_tipo_display()
            }
        return None

    def get_posicion_origen_info(self, obj):
        if obj.posicion_origen:
            return {
                'id': obj.posicion_origen.id,
                'nombre': obj.posicion_origen.nombre,
                'piso': obj.posicion_origen.piso.nombre if obj.posicion_origen.piso else None,
                'piso_id': obj.posicion_origen.piso.id if obj.posicion_origen.piso else None,
                'sede': obj.posicion_origen.sede.nombre if obj.posicion_origen.sede else None
            }
        return None

    def get_posicion_destino_info(self, obj):
        if obj.posicion_destino:
            return {
                'id': obj.posicion_destino.id,
                'nombre': obj.posicion_destino.nombre,
                'piso': obj.posicion_destino.piso.nombre if obj.posicion_destino.piso else None,
                'piso_id': obj.posicion_destino.piso.id if obj.posicion_destino.piso else None,
                'sede': obj.posicion_destino.sede.nombre if obj.posicion_destino.sede else None
            }
        return None

    def get_encargado_info(self, obj):
        if obj.encargado:
            return {
                'id': obj.encargado.id,
                'nombre': obj.encargado.nombre,
                'email': obj.encargado.email
            }
        return None

    def get_sede_info(self, obj):
        if obj.sede:
            return {
                'id': obj.sede.id,
                'nombre': obj.sede.nombre
            }
        return None

    def validate(self, data):
        """
        Validaciones personalizadas para los movimientos
        """
        pos_destino = data.get('posicion_destino')
        
        if pos_destino:
            # Verificar que la posición destino no esté llena
            if pos_destino.dispositivos.count() >= Posicion.MAX_DISPOSITIVOS:
                raise serializers.ValidationError(
                    {'posicion_destino': f'La posición ya tiene el máximo de {Posicion.MAX_DISPOSITIVOS} dispositivos'}
                )
            
            # Verificar que dispositivo y posición destino pertenezcan a la misma sede
            dispositivo = data.get('dispositivo')
            if dispositivo and dispositivo.sede != pos_destino.sede:
                raise serializers.ValidationError(
                    {'posicion_destino': 'El dispositivo y la posición destino deben pertenecer a la misma sede'}
                )
        
        return data

    def create(self, validated_data):
        """
        Sobreescribe el método create para asignar automáticamente el usuario logueado
        """
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            user = request.user
            if hasattr(user, 'roluser'):
                validated_data['encargado'] = user.roluser
        
        return super().create(validated_data)
    
    
    
class UsuarioExternoSerializer(serializers.ModelSerializer):
    tipo_documento_display = serializers.CharField(
        source='get_tipo_documento_display', 
        read_only=True
    )
    
    class Meta:
        model = UsuarioExterno
        fields = [
            'id',
            'tipo_documento',
            'tipo_documento_display',
            'documento',
            'nombre_completo',
            'cargo',
            'telefono',
            'email',
            'fecha_registro',
            'activo'
        ]
        extra_kwargs = {
            'documento': {'validators': []}  # Opcional: Para evitar validación de unique en updates
        }


class AsignacionDispositivoSerializer(serializers.ModelSerializer):
    dispositivo_info = serializers.SerializerMethodField()
    usuario_info = serializers.SerializerMethodField()
    asignado_por_info = serializers.SerializerMethodField()

    class Meta:
        model = AsignacionDispositivo
        fields = [
            'id',
            'usuario',
            'usuario_info',
            'dispositivo',
            'dispositivo_info',
            'fecha_asignacion',
            'fecha_devolucion',
            'estado',
            'ubicacion_asignada',
            'asignado_por',
            'asignado_por_info'
        ]
        extra_kwargs = {
            'usuario': {'write_only': True},
            'dispositivo': {'write_only': True},
            'asignado_por': {'write_only': True}
        }

    def get_dispositivo_info(self, obj):
        return {
            'id': obj.dispositivo.id,
            'serial': obj.dispositivo.serial,
            'marca': obj.dispositivo.marca, 
            'tipo': obj.dispositivo.get_tipo_display(),
            'modelo': obj.dispositivo.modelo  
           
        }

    def get_usuario_info(self, obj):
        return {
            'id': obj.usuario.id,
            'nombre': obj.usuario.nombre_completo,
            'documento': f"{obj.usuario.get_tipo_documento_display()} {obj.usuario.documento}",
            'cargo': obj.usuario.cargo
        }

    def get_asignado_por_info(self, obj):
        if obj.asignado_por:
            return {
                'id': obj.asignado_por.id,
                'nombre': obj.asignado_por.get_full_name(),
                'rol': obj.asignado_por.rol
            }
        return None
    

class AsignacionDispositivoCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AsignacionDispositivo
        fields = ['usuario', 'dispositivo', 'ubicacion_asignada', 'asignado_por']
        extra_kwargs = {
            'asignado_por': {'required': False}  # Se establecerá en la vista
        }

    def validate(self, data):
        dispositivo = data.get('dispositivo')
        
        if not dispositivo:
            raise serializers.ValidationError({
                'dispositivo': 'Se requiere un dispositivo'
            })
        
        # Estados permitidos para asignación
        estados_permitidos = ['BUENO', 'BODEGA_CN', 'BODEGA', 'SEDE', 'STOCK']
        
        if dispositivo.estado not in estados_permitidos:
            raise serializers.ValidationError({
                'dispositivo': f'El dispositivo no está en un estado asignable. Estado actual: {dispositivo.get_estado_display()}'
            })
            
        if dispositivo.estado_uso != 'DISPONIBLE':
            raise serializers.ValidationError({
                'dispositivo': 'El dispositivo no está disponible para asignación'
            })
            
        return data

class RolUserLiteSerializer(serializers.ModelSerializer):
    class Meta:
        model  = RolUser
        fields = ("id", "nombre", "username", "email", "celular", "documento")

class RegistroMovimientoDispositivoSerializer(serializers.ModelSerializer):
    asignacion_info = serializers.SerializerMethodField()
    registrado_por_info  = RolUserLiteSerializer(source="registrado_por", read_only=True)
    estado_actual = serializers.SerializerMethodField()
    tipo_siguiente = serializers.SerializerMethodField()

    class Meta:
        model = RegistroMovimientoDispositivo
        fields = [
            'id',
            'asignacion',
            'asignacion_info',
            'tipo',
            'fecha',
            'hora',
            'observaciones',
            'registrado_por',
            'registrado_por_info',
            'estado_actual',
            'tipo_siguiente'
        ]
        extra_kwargs = {
            'asignacion': {'write_only': True},
            'registrado_por': {'write_only': True}
        }

    def get_asignacion_info(self, obj):
        return {
            'usuario': {
                'nombre': obj.asignacion.usuario.nombre_completo,
                "documento": f"{obj.asignacion.usuario.get_tipo_documento_display()} {obj.asignacion.usuario.documento}",
                "documento_num": obj.asignacion.usuario.documento,
                'cargo': obj.asignacion.usuario.cargo
            },
            'dispositivo': {
                'serial': obj.asignacion.dispositivo.serial,
                'tipo': obj.asignacion.dispositivo.get_tipo_display(),
                'modelo': obj.asignacion.dispositivo.modelo,
                'marca': obj.asignacion.dispositivo.marca,
            }
        }

    def get_estado_actual(self, obj):
        # Aquí calculamos el estado actual en función del último movimiento
        ultimo_movimiento = RegistroMovimientoDispositivo.objects.filter(asignacion=obj.asignacion).order_by('-fecha', '-hora').first()
        if not ultimo_movimiento:
            return "Fuera"
        elif ultimo_movimiento.tipo == 'ENTRADA':
            return "Dentro"
        else:
            return "Fuera"

    def get_tipo_siguiente(self, obj):
        # Aquí calculamos el tipo de movimiento siguiente en función del último movimiento
        ultimo_movimiento = RegistroMovimientoDispositivo.objects.filter(asignacion=obj.asignacion).order_by('-fecha', '-hora').first()
        if not ultimo_movimiento:
            return "ENTRADA"
        elif ultimo_movimiento.tipo == 'ENTRADA':
            return "SALIDA"
        else:
            return "ENTRADA"
        
    def validate(self, data):
        # Obtener el último movimiento
        ultimo_movimiento = RegistroMovimientoDispositivo.objects.filter(
            asignacion=data['asignacion']
        ).order_by('-fecha', '-hora').first()
        
        tipo_actual = data['tipo']
        
        if ultimo_movimiento:
            if ultimo_movimiento.tipo == tipo_actual:
                raise serializers.ValidationError(
                    f"No puede registrar una {tipo_actual.lower()} consecutiva. "
                    f"Primero debe registrar una {'SALIDA' if tipo_actual == 'ENTRADA' else 'ENTRADA'}."
                )
        
        # Validación adicional: No permitir SALIDA si no hay ENTRADA previa
        if tipo_actual == 'SALIDA' and not ultimo_movimiento:
            raise serializers.ValidationError(
                "No puede registrar una SALIDA sin una ENTRADA previa."
            )
            
        return data



class PisoSerializer(serializers.ModelSerializer):
    sede_nombre = serializers.CharField(source='sede.nombre', read_only=True)
    es_principal_display = serializers.CharField(source='get_es_principal_display', read_only=True)

    class Meta:
        model = Piso
        fields = ['id', 'nombre', 'sede', 'sede_nombre', 'orden', 'es_principal', 'es_principal_display']
        extra_kwargs = {'sede': {'required': True}}

    def validate(self, data):
        if Piso.objects.filter(nombre=data['nombre'], sede=data['sede']).exists():
            raise serializers.ValidationError("Ya existe un piso con este nombre en la sede seleccionada.")
        return data

class SubPisoSerializer(serializers.ModelSerializer):
    piso_padre_nombre = serializers.CharField(source='piso_padre.nombre', read_only=True)
    sede_nombre = serializers.CharField(source='sede.nombre', read_only=True)

    class Meta:
        model = SubPiso
        fields = ['id', 'nombre', 'piso_padre', 'piso_padre_nombre', 'descripcion', 'orden', 'sede', 'sede_nombre']
        extra_kwargs = {
            'piso_padre': {'required': True},
            'sede': {'read_only': True}
        }

    def validate_piso_padre(self, value):
        if not value.es_principal:
            raise serializers.ValidationError("El piso padre debe ser un piso principal.")
        return value

    def create(self, validated_data):
        validated_data['sede'] = validated_data['piso_padre'].sede
        return super().create(validated_data)
    
    
class PosicionMovimientoSerializer(serializers.ModelSerializer):
    piso_nombre = serializers.CharField(source='piso.nombre', read_only=True)
    subpiso_nombre = serializers.CharField(source='subpiso.nombre', read_only=True, allow_null=True)
    
    class Meta:
        model = Posicion
        fields = ['id', 'nombre', 'piso', 'sede',  'piso_nombre', 'subpiso', 'subpiso_nombre', 'fila', 'columna']