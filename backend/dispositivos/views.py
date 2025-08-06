import logging
import time
from datetime import datetime, timedelta
import jwt # type: ignore
import pandas as pd  # type: ignore
from fuzzywuzzy import process  # type: ignore
from django.conf import settings  # type: ignore
from django.core.exceptions import ObjectDoesNotExist # type: ignore
from django.core.mail import send_mail  # type: ignore
from django.db import IntegrityError, transaction # type: ignore
from django.db.models import Count, ExpressionWrapper, F, FloatField, Q, Sum # type: ignore
from django.http import JsonResponse # type: ignore
from django.shortcuts import get_object_or_404, render # type: ignore
from django.utils import timezone # type: ignore
from django.views.decorators.cache import never_cache, cache_control # type: ignore
from django.views.decorators.csrf import csrf_exempt # type: ignore
from django.contrib.auth import authenticate, login as django_login # type: ignore
from django.contrib.auth.hashers import make_password  # type: ignore
from django.contrib.auth.models import User # type: ignore
from django.contrib.auth.decorators import login_required  # type: ignore
from rest_framework import viewsets, filters, status, generics # type: ignore
from rest_framework.pagination import PageNumberPagination # type: ignore
from rest_framework.authentication import TokenAuthentication # type: ignore
from rest_framework.exceptions import ValidationError # type: ignore
from rest_framework.decorators import (  # type: ignore
    api_view, parser_classes, permission_classes,
    action, authentication_classes
) # type: ignore
from rest_framework.parsers import MultiPartParser # type: ignore
from rest_framework.permissions import AllowAny, IsAuthenticated # type: ignore
from rest_framework.response import Response # type: ignore
from django_filters.rest_framework import DjangoFilterBackend  # type: ignore
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken # type: ignore
from rest_framework_simplejwt.exceptions import TokenError # type: ignore
from .models import RolUser, Sede, Dispositivo, Servicios, Posicion, Historial, Movimiento, UsuarioExterno, AsignacionDispositivo, RegistroMovimientoDispositivo
from .serializers import (
    RolUserSerializer, ServiciosSerializer, LoginSerializer, PosicionMovimientoSerializer,
    DispositivoSerializer, SedeSerializer, PosicionSerializer, HistorialSerializer,  MovimientoSerializer, UsuarioExternoSerializer, AsignacionDispositivoSerializer, AsignacionDispositivoCreateSerializer
)
from .pagination import StandardPagination
from .utils import importar_excel, exportar_excel
from .serializers import UsuarioExternoSerializer, RegistroMovimientoDispositivoSerializer

logger = logging.getLogger(__name__)


@login_required
@never_cache  # Evita que se pueda acceder con "Atrás"
def dashboard(request):
    return render(request, 'dashboard.html')

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def dashboard(request):
    return Response({"message": "Bienvenido al dashboard"}) 

@api_view(['GET' ])
@permission_classes([IsAuthenticated])  # Solo los usuarios autenticados pueden acceder
def get_users_view(request):

    users = RolUser.objects.all()
    
    serializer = RolUserSerializer(users, many=True)

    return Response(serializer.data)

class RolUserViewSet(viewsets.ModelViewSet):
    queryset = RolUser.objects.all()
    serializer_class = RolUserSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def login_user(request):
    try:
        # Limpiar sesión existente
        if hasattr(request, 'session'):
            request.session.flush()

        username = request.data.get('username', '').strip()
        password = request.data.get('password', '').strip()
        sede_id = request.data.get('sede_id', None)

        if not username or not password:
            return Response(
                {'error': 'Usuario y contraseña requeridos'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(username=username, password=password)

        if not user:
            logger.warning(f"Intento fallido de login para usuario: {username}")
            return Response(
                {'error': 'Credenciales inválidas'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            logger.warning(f"Intento de login para usuario inactivo: {username}")
            return Response(
                {'error': 'Cuenta desactivada'},
                status=status.HTTP_403_FORBIDDEN
            )

        sede_nombre = None

        # Lógica según el rol
        if user.rol == 'admin':
            sede = None
            sede_id = None
            sede_nombre = None

        elif user.rol in ['coordinador', 'celador', 'seguridad']:
            if not sede_id:
                return Response(
                    {'error': 'Debe seleccionar una sede'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                sede = Sede.objects.get(id=sede_id)
                if not user.sedes.filter(id=sede_id).exists():
                    return Response(
                        {'error': 'No tiene permisos para acceder a esta sede'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                sede_nombre = sede.nombre
            except Sede.DoesNotExist:
                return Response(
                    {'error': 'Sede no encontrada'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            return Response(
                {'error': 'Rol de usuario no válido'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Iniciar sesión
        django_login(request, user)
        
        # Registrar última actividad (nuevo)
        user.last_activity = timezone.now()
        user.save(update_fields=['last_activity'])
        
        request.session['last_activity'] = timezone.now().isoformat()
        if sede_id:
            request.session['sede_id'] = sede_id

        refresh = RefreshToken.for_user(user)

        logger.info(f"Login exitoso para usuario: {username} (Rol: {user.rol})")

        # Configuración de tiempo de inactividad según rol
        inactivity_timeout = 0 if user.rol == 'celador' else 1800  # Celadores no tienen timeout

        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'username': user.username,
            'email': user.email,
            'rol': user.rol,
            'sede_id': sede_id,
            'sede_nombre': sede_nombre if user.rol in ['coordinador', 'celador', 'seguridad'] else None,
            'sessionid': request.session.session_key,
            'message': 'Autenticación exitosa',
            'inactivity_timeout': inactivity_timeout,
            'is_inactivity_exempt': user.rol == 'celador',  # Celadores están exentos
            'last_activity': user.last_activity.isoformat()
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error en login: {str(e)}", exc_info=True)
        return Response(
            {'error': 'Error interno del servidor'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def keepalive(request):
    """Endpoint para mantener la sesión activa"""
    try:
        # Solo actualizar actividad si no es celador
        if request.user.rol != 'celador':
            request.user.last_activity = timezone.now()
            request.user.save(update_fields=['last_activity'])
            
            request.session['last_activity'] = timezone.now().isoformat()
            request.session.modified = True
        
        return Response({
            "status": "active",
            "is_exempt": request.user.rol == 'celador',
            "user": {
                "id": request.user.id,
                "rol": request.user.rol,
                "username": request.user.username
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error en keepalive: {str(e)}", exc_info=True)
        return Response(
            {"error": "Error al actualizar actividad"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
@api_view(["GET"])  # Cambiado a GET ya que es una verificación
@permission_classes([])
def validate_token(request):
    auth_header = request.headers.get("Authorization")
    
    if not auth_header:
        return Response(
            {"error": "Token no proporcionado"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Verificar formato del header
        if not auth_header.startswith("Bearer "):
            raise TokenError("Formato de token inválido")
            
        token = auth_header.split(" ")[1]
        AccessToken(token).verify()  # Verifica expiración y firma
        
        return Response({
            "message": "Token válido",
            "is_valid": True
        }, status=status.HTTP_200_OK)
        
    except TokenError as e:
        return Response({
            "error": str(e),
            "is_valid": False
        }, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({
            "error": "Error al procesar el token",
            "details": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(['GET'])
@permission_classes([AllowAny])
def obtener_datos_protegidos(request):
    return Response({"message": "Datos protegidos disponibles solo para usuarios autenticados"})
@api_view(['GET'])
@permission_classes([])  
def get_users_view(request):
    users = RolUser.objects.all()
    serializer = RolUserSerializer(users, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_detail_view(request, user_id):
    try:
        user = RolUser.objects.get(id=user_id)
    except RolUser.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=404)

    serializer = RolUserSerializer(user)
    return Response(serializer.data, status=200)

@api_view(['PUT'])
@permission_classes([])  # Sin permisos de autenticación
def activate_user_view(request, user_id):

    try:
        user = RolUser.objects.get(id=user_id)
    except RolUser.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

    if user.is_active:
        return Response({"message": "El usuario ya está activo."}, status=status.HTTP_400_BAD_REQUEST)

    user.is_active = True
    user.save()
    return Response({"message": "Usuario activado exitosamente."}, status=status.HTTP_200_OK)

@api_view(['PUT'])
@permission_classes([])  # Sin permisos de autenticación
def deactivate_user_view(request, user_id):
    """
    Desactiva un usuario cambiando el campo 'is_active' a False.
    """
    try:
        user = RolUser.objects.get(id=user_id)
    except RolUser.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

    if not user.is_active:
        return Response({"message": "El usuario ya está desactivado."}, status=status.HTTP_400_BAD_REQUEST)

    user.is_active = False
    user.save()
    return Response({"message": "Usuario desactivado exitosamente."}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_user_detail_view(request, user_id):

    try:
        # Obtener el usuario por ID
        user = RolUser.objects.get(id=user_id)
    except RolUser.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

    # Serializar y devolver los datos del usuario
    serializer = RolUserSerializer(user)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def register_user_view(request):
    data = request.data

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    email = data.get('email', '').strip().lower()
    nombre = data.get('nombre', '').strip()
    celular = data.get('celular', '').strip()
    documento = data.get('documento', '').strip()
    rol = data.get('rol', 'coordinador')
    sedes_ids = data.get('sedes', [])  # Lista de IDs de sedes

    if not username or not email or not password or not confirm_password:
        return Response({"error": "Todos los campos son obligatorios."}, status=status.HTTP_400_BAD_REQUEST)

    if password != confirm_password:
        return Response({"error": "Las contraseñas no coinciden."}, status=status.HTTP_400_BAD_REQUEST)

    if rol != 'admin' and not sedes_ids:
        return Response({"error": "Debe seleccionar al menos una sede para coordinadores."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Verificar que las sedes existen
        sedes = Sede.objects.filter(id__in=sedes_ids)
        if sedes.count() != len(sedes_ids):
            return Response({"error": "Una o más sedes no existen."}, status=status.HTTP_400_BAD_REQUEST)

        user = RolUser.objects.create(
            username=username,
            email=email,
            rol=rol,
            nombre=nombre,
            celular=celular,
            documento=documento,
            password=make_password(password),
            is_active=True
        )

        user.sedes.set(sedes)
        return Response({"message": "Usuario registrado exitosamente."}, status=status.HTTP_201_CREATED)

    except IntegrityError as e:
        logger.error(f"Error de integridad al registrar usuario: {str(e)}")
        return Response({"error": "El nombre de usuario o correo ya existe."}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Error al registrar el usuario: {str(e)}")
        return Response({"error": "Ocurrió un error al registrar el usuario."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from datetime import datetime

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def reset_password_request(request):
    email = request.data.get('email', '').strip().lower()
    if not email:
        return Response({"error": "El correo es un campo obligatorio."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = RolUser.objects.get(email=email)
    except RolUser.DoesNotExist:
        return Response({"error": "El correo no existe."}, status=status.HTTP_404_NOT_FOUND)

    try:
        reset_link = f"{settings.FRONTEND_URL}/reset-password?email={email}"
        
        # Contexto para el template
        context = {
            'username': user.username or user.email,
            'email': user.email,
            'reset_link': reset_link,
            'fecha': datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'company_name': settings.COMPANY_NAME or "EmergiaCC"
        }
        
        # Renderizar el template HTML
        html_content = render_to_string('emails/reset_password.html', context)
        text_content = strip_tags(html_content)  # Versión en texto plano
        
        subject = "Restablecimiento de contraseña"
        
        msg = EmailMultiAlternatives(
            subject,
            text_content,
            settings.DEFAULT_FROM_EMAIL,
            [email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        
        return Response({"message": "Se ha enviado un correo con instrucciones para restablecer tu contraseña."}, 
                    status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error al enviar el correo: {str(e)}")
        return Response({"error": "Ocurrió un error al procesar tu solicitud. Por favor, inténtalo de nuevo más tarde."}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET' , 'POST'])
@permission_classes([AllowAny]) 
def reset_password(request):

    email = request.data.get('email', '').strip().lower()
    new_password = request.data.get('password', '').strip()

    if not email or not new_password:
        return Response({"error": "Correo y nueva contraseña son obligatorios."}, status=status.HTTP_400_BAD_REQUEST)

    if len(new_password) < 8:
        return Response({"error": "La contraseña debe tener al menos 8 caracteres."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = RolUser.objects.get(email=email)
        user.password = make_password(new_password)
        user.save()
        return Response({"message": "Contraseña cambiada exitosamente."}, status=status.HTTP_200_OK)
    except RolUser.DoesNotExist:
        return Response({"error": "El correo no está registrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": f"Error al cambiar la contraseña: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny]) 
def get_sedes_view(request):
    try:
        sedes = Sede.objects.all().values('id', 'nombre', 'ciudad', 'direccion')
        return Response({"sedes": list(sedes)}, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error al obtener las sedes: {str(e)}")
        return Response({"error": "Ocurrió un error al obtener las sedes."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['PUT'])
@permission_classes([AllowAny])
def edit_user_view(request, user_id):
    try:
        user = RolUser.objects.get(id=user_id)
    except RolUser.DoesNotExist:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

    data = request.data
    sedes_ids = data.get('sedes', [])

    # Validación para coordinadores
    if user.rol != 'admin' and not sedes_ids:
        return Response({"error": "Debe seleccionar al menos una sede para coordinadores."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Verificar que las sedes existen
        sedes = Sede.objects.filter(id__in=sedes_ids)
        if sedes.count() != len(sedes_ids):
            return Response({"error": "Una o más sedes no existen."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = RolUserSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            user = serializer.save()
            user.sedes.set(sedes)
            return Response({"message": "Usuario actualizado exitosamente."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error al actualizar usuario: {str(e)}")
        return Response({"error": "Ocurrió un error al actualizar el usuario."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def dispositivo_view(request):
    if request.method == 'GET':
        try:
            queryset = Dispositivo.objects.select_related('posicion', 'sede')
            
            # Filtrado por sede si se proporciona
            sede_id = request.query_params.get('sede_id')
            if sede_id:
                queryset = queryset.filter(sede_id=sede_id)
            
            # Filtrado por posición si se proporciona
            posicion_id = request.query_params.get('posicion_id')
            if posicion_id:
                queryset = queryset.filter(posicion_id=posicion_id)
            
            dispositivos = queryset.all()
            serializer = DispositivoSerializer(dispositivos, many=True)
            
            return Response({
                'data': serializer.data,
                'count': len(serializer.data),
                'filters': {
                    'sede_id': sede_id,
                    'posicion_id': posicion_id
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error al obtener dispositivos: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error interno del servidor al obtener dispositivos"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    elif request.method == 'POST':
        serializer = DispositivoSerializer(
            data=request.data,
            context={'request': request}  # Pasar el request al serializer
        )
        
        if not serializer.is_valid():
            return Response({
                'error': 'Datos inválidos',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                # Validación de serial único (hecha en el serializer también)
                if Dispositivo.objects.filter(serial=serializer.validated_data['serial']).exists():
                    return Response(
                        {"error": "El serial del dispositivo ya existe en el sistema"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                dispositivo = serializer.save()
                
                # Respuesta con datos completos incluyendo relaciones
                full_serializer = DispositivoSerializer(dispositivo)
                return Response(
                    full_serializer.data,
                    status=status.HTTP_201_CREATED
                )
                
        except IntegrityError as e:
            logger.error(f"Error de integridad al crear dispositivo: {str(e)}")
            return Response(
                {"error": "Error de integridad de datos - posible duplicado o relación inválida"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error al crear dispositivo: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error interno del servidor al crear dispositivo"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([AllowAny])
def dispositivo_detail_view(request, dispositivo_id):
    try:
        dispositivo = Dispositivo.objects.select_related(
            'posicion', 'sede'
        ).get(id=dispositivo_id)
    except Dispositivo.DoesNotExist:
        return Response(
            {"error": "Dispositivo no encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )

    if request.method == 'GET':
        serializer = DispositivoSerializer(dispositivo)
        return Response(serializer.data)

    elif request.method == 'PUT':
        try:
            serializer = DispositivoSerializer(
                dispositivo, 
                data=request.data, 
                partial=True,
                context={'request': request}
            )
            
            if not serializer.is_valid():
                return Response({
                    'error': 'Datos de actualización inválidos',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic():
                # Validación adicional de serial único
                if 'serial' in request.data:
                    new_serial = request.data['serial']
                    if Dispositivo.objects.filter(serial=new_serial).exclude(id=dispositivo_id).exists():
                        return Response(
                            {"error": "El nuevo serial ya pertenece a otro dispositivo"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                
                dispositivo_actualizado = serializer.save()
                
                # Respuesta con datos completos
                full_serializer = DispositivoSerializer(dispositivo_actualizado)
                return Response(full_serializer.data)
                
        except IntegrityError as e:
            logger.error(f"Error de integridad al actualizar dispositivo {dispositivo_id}: {str(e)}")
            return Response(
                {"error": "Error de integridad en la actualización"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error al actualizar dispositivo {dispositivo_id}: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error interno al actualizar dispositivo"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    elif request.method == 'DELETE':
        try:
            with transaction.atomic():
                dispositivo.delete()
                return Response(
                    status=status.HTTP_204_NO_CONTENT
                )
        except Exception as e:
            logger.error(f"Error al eliminar dispositivo {dispositivo_id}: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error interno al eliminar dispositivo"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

@api_view(['GET'])
@permission_classes([AllowAny])
def posiciones_por_sede_view(request, sede_id):
    try:
        # Validar que el ID sea un número entero
        try:
            sede_id_int = int(sede_id)
            if sede_id_int <= 0:
                raise ValueError("El ID debe ser positivo")
        except ValueError:
            return Response(
                {"error": "El ID de sede debe ser un número entero positivo"},
                status=status.HTTP_400_BAD_REQUEST
            )
        posiciones = Posicion.objects.filter(sede_id=sede_id_int)\
            .select_related('sede')\
            .only('id', 'nombre', 'piso', 'sede')
    
        if not posiciones.exists():
            return Response(
                {"warning": f"No se encontraron posiciones para la sede ID {sede_id}"},
                status=status.HTTP_200_OK
            )
        return Response([{
            'id': p.id,
            'nombre': p.nombre,
            'piso': p.piso,
            'sede_id': p.sede.id if p.sede else None,
            'sede_nombre': p.sede.nombre if p.sede else 'Sin sede'
        } for p in posiciones])
        
    except Exception as e:
        logger.error(f"Error al obtener posiciones para sede {sede_id}: {str(e)}", exc_info=True)
        return Response(
            {"error": "Error interno al obtener posiciones"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
      
        
        
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def servicios_view(request):
    if request.method == 'GET':
        # Obtener todos los servicios
        servicios = Servicios.objects.all()
        serializer = ServiciosSerializer(servicios, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'POST':
        data = request.data
        nombre = data.get('nombre', '').strip()
        codigo_analitico = data.get('codigo_analitico', '').strip()
        sedes_ids = data.get('sedes', [])  # 🔹 Asegurar que es una lista
    
        if not nombre:
            return Response({"error": "El campo 'nombre' es obligatorio."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            servicio = Servicios.objects.create(
                nombre=nombre,
                codigo_analitico=codigo_analitico,
                color=data.get('color', '#FFFFFF')
            )
            servicio.sedes.set(sedes_ids)  # 🔹 Asignar múltiples sedes correctamente
            return Response({"message": "Servicio creado exitosamente."}, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error al crear el servicio: {str(e)}")
            return Response({"error": "Ocurrió un error al crear el servicio."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([AllowAny])
def servicio_detail_view(request, servicio_id):
    try:
        # Intentar obtener el servicio por su ID
        servicio = Servicios.objects.get(id=servicio_id)
    except Servicios.DoesNotExist:
        return Response({"error": "El servicio no existe."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        # Obtener los detalles del servicio
        serializer = ServiciosSerializer(servicio)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        data = request.data
        servicio.nombre = data.get('nombre', servicio.nombre).strip()
        servicio.codigo_analitico = data.get('codigo_analitico', servicio.codigo_analitico).strip()
        servicio.color = data.get('color', servicio.color).strip() 
        sedes_ids = data.get('sedes', [])  # 🔹 Asegurar que es una lista
        servicio.sedes.set(sedes_ids)  # 🔹 Asignar correctamente la relación ManyToMany

        if not servicio.nombre:
            return Response({"error": "El campo 'nombre' es obligatorio."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            servicio.save()
            return Response({"message": "Servicio actualizado exitosamente."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error al actualizar el servicio: {str(e)}")
            return Response({"error": "Ocurrió un error al actualizar el servicio."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    elif request.method == 'DELETE':
        # Eliminar el servicio
        try:
            servicio.delete()
            return Response({"message": "Servicio eliminado exitosamente."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error al eliminar el servicio: {str(e)}")
            return Response({"error": "Ocurrió un error al eliminar el servicio."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(['GET', 'POST'])  # Asegúrate de incluir 'POST' aquí
@permission_classes([AllowAny])
def sede_view(request):
    if request.method == 'GET':
        # Listar todas las sedes
        sedes = Sede.objects.all()
        serializer = SedeSerializer(sedes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'POST':
        # Crear una nueva sede
        data = request.data

        nombre = data.get('nombre', '').strip()
        direccion = data.get('direccion', '').strip()
        ciudad = data.get('ciudad', '').strip()

        # Validar campos obligatorios
        if not nombre or not direccion or not ciudad:
            return Response({"error": "Todos los campos son obligatorios."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            sede = Sede.objects.create(nombre=nombre, direccion=direccion, ciudad=ciudad)
            return Response({"message": "Sede creada exitosamente."}, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error al crear la sede: {str(e)}")
            return Response({"error": "Ocurrió un error al crear la sede."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([AllowAny])
def sede_detail_view(request, sede_id):
    try:
        # Intentar obtener la sede por su ID
        sede = Sede.objects.get(id=sede_id)
    except Sede.DoesNotExist:
        return Response({"error": "La sede no existe."}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        # Obtener los detalles de la sede
        serializer = SedeSerializer(sede)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        # Actualizar los detalles de la sede
        data = request.data

        sede.nombre = data.get('nombre', sede.nombre).strip()
        sede.direccion = data.get('direccion', sede.direccion).strip()
        sede.ciudad = data.get('ciudad', sede.ciudad).strip()

        # Validar campos obligatorios
        if not sede.nombre:
            return Response({"error": "El campo 'nombre' es obligatorio."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Guardar cambios
            sede.save()
            return Response({"message": "Sede actualizada exitosamente."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error al actualizar la sede: {str(e)}")
            return Response({"error": "Ocurrió un error al actualizar la sede."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'DELETE':
        # Eliminar la sede
        try:
            sede.delete()
            return Response({"message": "Sede eliminada exitosamente."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error al eliminar la sede: {str(e)}")
            return Response({"error": "Ocurrió un error al eliminar la sede."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# vistas para las posiciones
@api_view(['GET'])
@permission_classes([AllowAny])
def posiciones_view(request):
    posiciones = Posicion.objects.all().prefetch_related('dispositivos')
    serializer = PosicionSerializer(posiciones, many=True)

    return Response(serializer.data, status=200)

@api_view(['GET'])
@permission_classes([]) 
def dashboard_data(request):
    sede_id = request.query_params.get('sede')
    
    if sede_id == "null":
        dispositivos = Dispositivo.objects.filter(sede__isnull=True)
    elif sede_id:
        try:
            sede_id = int(sede_id)
            dispositivos = Dispositivo.objects.filter(sede_id=sede_id)
        except (ValueError, TypeError):
            return Response({"error": "ID de sede inválido"}, status=400)
    else:
        dispositivos = Dispositivo.objects.all()

    total_dispositivos = dispositivos.count()
    dispositivos_en_uso = dispositivos.filter(estado_uso='EN_USO').count()
    dispositivos_buen_estado = dispositivos.filter(estado='BUENO').count()
    dispositivos_disponibles = dispositivos.filter(estado_uso='DISPONIBLE').count()
    dispositivos_en_reparacion = dispositivos.filter(estado='REPARAR').count()
    dispositivos_perdidos = dispositivos.filter(estado='PERDIDO').count()
    dispositivos_mal_estado = dispositivos.filter(estado='MALO').count()
    dispositivos_inhabilitados = dispositivos.filter(estado_uso='INHABILITADO').count()

    cardsData = [
        {
            "title": "Total dispositivos",
            "value": total_dispositivos,
            "date": "Actualizado hoy"
        },
        {
            "title": "Dispositivos en uso",
            "value": dispositivos_en_uso,
            "date": "Actualizado hoy"
        },
        {
            "title": "Buen estado",
            "value": dispositivos_buen_estado,
            "date": "Actualizado hoy"
        },
        {
            "title": "Dispositivos disponibles",
            "value": dispositivos_disponibles,
            "date": "Actualizado hoy"
        },
        {
            "title": "En reparación",
            "value": dispositivos_en_reparacion,
            "date": "Actualizado hoy"
        },
        {
            "title": "Perdidos/robados",
            "value": dispositivos_perdidos,
            "date": "Actualizado hoy"
        },
        {
            "title": "Mal estado",
            "value": dispositivos_mal_estado,
            "date": "Actualizado hoy"
        },
        {
            "title": "Inhabilitados",
            "value": dispositivos_inhabilitados,
            "date": "Actualizado hoy"
        }
    ]

    return Response({"cardsData": cardsData})

def encontrar_servicio_mas_parecido(nombre_servicio):
    if not nombre_servicio:
        return None
    servicios = Servicios.objects.values_list('nombre', 'codigo_analitico')
    if not servicios.exists():
        return None
    mejor_coincidencia, puntuacion = process.extractOne(nombre_servicio, [s[0] for s in servicios])
    if puntuacion >= 80:
        return next((s for s in servicios if s[0] == mejor_coincidencia), None)
    return None


@api_view(['POST', 'GET'])
@permission_classes([AllowAny])
def importar_dispositivos(request):
    if 'file' not in request.FILES:
        return Response({'error': 'No se proporcionó archivo'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        file = request.FILES['file']
        sede_id = request.POST.get('sede_id')

        if not sede_id:
            return Response({'error': 'No se proporcionó ID de sede'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            sede = Sede.objects.get(id=sede_id)
        except Sede.DoesNotExist:
            return Response({'error': f'Sede con ID {sede_id} no encontrada'}, status=status.HTTP_400_BAD_REQUEST)

        if not file.name.endswith(('.xlsx', '.xls')):
            return Response({'error': 'Formato de archivo no válido. Solo se aceptan .xlsx o .xls'}, 
                        status=status.HTTP_400_BAD_REQUEST)

        if file.size > 10 * 1024 * 1024:
            return Response({'error': 'El archivo es demasiado grande (máximo 10MB)'}, 
                        status=status.HTTP_400_BAD_REQUEST)

        # Función para limpiar cédulas
        def clean_cedula(cedula_str):
            # Convertir a string por si viene como número
            cedula = str(cedula_str).strip().upper()
            
            # Eliminar ".0" al final si existe
            if cedula.endswith('.0'):
                cedula = cedula[:-2]
            
            # Manejar notación científica (ej: "1,11E+09" → "1110000000")
            if 'E+' in cedula:
                try:
                    # Reemplazar coma por punto para float
                    cedula = cedula.replace(',', '.')
                    cedula = "{:.0f}".format(float(cedula))
                except ValueError:
                    pass
            
            # Eliminar todos los caracteres no numéricos
            cedula = ''.join(c for c in cedula if c.isdigit())
            
            return cedula if cedula else None

        # Listas de valores válidos
        TIPOS_DISPOSITIVOS_VALIDOS = [x[0] for x in Dispositivo.TIPOS_DISPOSITIVOS]
        ESTADOS_VALIDOS = [x[0] for x in Dispositivo.ESTADO_DISPOSITIVO]

        try:
            # Leer el archivo Excel
            df = pd.read_excel(file)
            logger.info(f"Columnas detectadas en el archivo: {df.columns.tolist()}")

            def normalize_column_name(col):
                col = str(col).upper().strip()
                col = col.replace(' ', '_').replace('Ó', 'O').replace('É', 'E').replace('Á', 'A')
                col = col.replace('Í', 'I').replace('Ú', 'U').replace('Ñ', 'N')
                return col

            df.columns = [normalize_column_name(col) for col in df.columns]
            logger.info(f"Columnas normalizadas: {df.columns.tolist()}")

            column_mappings = {
                'CODIGO_ANALITICO': ['CODIGO_ANALITICO', 'CODIGO'],
                'NOMBRE': ['NOMBRE'],
                'CEDULA': ['CEDULA', 'DOCUMENTO'],
                'CARGO': ['CARGO', 'PUESTO'],
                'REFERENCIA': ['MODELO', 'REFERENCIA'],
                'TELEFONO': ['TELEFONO', 'CELULAR'],
                'GENERACION': ['GENERACION', 'GEN']
            }

            required_columns = ['PISO', 'POSICION', 'SERVICIO', 'CODIGO_ANALITICO', 'TIPO_DISPOSITIVO', 
                            'FABRICANTE', 'SERIAL', 'CU', 'GENERACION', 'TPM']

            missing_columns = []
            for col in required_columns:
                if col not in df.columns:
                    if col in column_mappings:
                        for alt_col in column_mappings[col]:
                            if alt_col in df.columns:
                                df.rename(columns={alt_col: col}, inplace=True)
                                break
                    if col not in df.columns:
                        missing_columns.append(col)

            if missing_columns:
                return Response({'error': f'Faltan columnas requeridas: {", ".join(missing_columns)}'}, 
                              status=status.HTTP_400_BAD_REQUEST)

            # Asegurar columnas de usuario
            user_columns = ['NOMBRE', 'CEDULA', 'CARGO']
            for col in user_columns:
                if col not in df.columns:
                    df[col] = ''

            # Limpieza de datos
            df = df.fillna('')
            for col in df.columns:
                if col == 'CEDULA':
                    # Aplicar clean_cedula solo a la columna CEDULA
                    df[col] = df[col].astype(str).apply(lambda x: clean_cedula(x) or '')
                else:
                    df[col] = df[col].astype(str).apply(lambda x: x.strip().upper())

        except Exception as e:
            return Response({'error': f'Error al procesar el archivo Excel: {str(e)}'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        if df.empty:
            return Response({'error': 'El archivo está vacío'}, status=status.HTTP_400_BAD_REQUEST)

        total_rows = len(df)
        created = 0
        updated = 0
        errors = []
        batch_size = 100

        with transaction.atomic():
            for i in range(0, total_rows, batch_size):
                batch = df.iloc[i:i + batch_size]

                for idx, row in batch.iterrows():
                    row_num = idx + 2
                    try:
                        serial = row.get('SERIAL', '').strip()
                        cu = row.get('CU', '').strip()
                        tipo_dispositivo = row.get('TIPO_DISPOSITIVO', 'COMPUTADOR').strip()
                        
                        # Validar tipo de dispositivo
                        if tipo_dispositivo not in TIPOS_DISPOSITIVOS_VALIDOS:
                            errors.append(f"Fila {row_num}: Tipo de dispositivo '{tipo_dispositivo}' no válido. Valores permitidos: {', '.join(TIPOS_DISPOSITIVOS_VALIDOS)}")
                            continue
                        
                        referencia = row.get('REFERENCIA', '').strip()
                        modelo = row.get('MODELO', referencia).strip() or 'SIN MODELO'
                        
                        # Manejar TPM como número
                        try:
                            tpm = float(row.get('TPM', '0')) if row.get('TPM', '') else None
                        except ValueError:
                            tpm = None
                            errors.append(f"Fila {row_num}: Valor de TPM no válido, se establecerá como NULL")
                        
                        estado = row.get('ESTADO', 'BUENO').strip()
                        if estado not in ESTADOS_VALIDOS:
                            estado = 'BUENO'
                            errors.append(f"Fila {row_num}: Estado no válido, se usará 'BUENO'")

                        if not serial and not cu:
                            continue

                        es_portatil = tipo_dispositivo == 'PORTATIL'
                        
                        # Procesamiento de PISO y SUBPISO (modificado para manejar "P1 OP")
                        piso_raw = row.get('PISO', '').strip()
                        
                        # Caso especial para "P1 OP" y similares
                        partes = piso_raw.split()
                        piso_nombre = partes[0] if partes else None
                        subpiso_nombre = partes[1] if len(partes) > 1 else None

                        # Buscar/crear piso
                        piso = None
                        if piso_nombre and piso_nombre != '-':
                            try:
                                piso = Piso.objects.get(nombre=piso_nombre, sede=sede)
                            except Piso.DoesNotExist:
                                pass  # No se crea, se deja como null
    
                        # Buscar/crear subpiso
                        subpiso = None
                        if subpiso_nombre and piso:  # Solo buscar subpiso si existe el piso
                            try:
                                subpiso = SubPiso.objects.get(nombre=subpiso_nombre, piso_padre=piso)
                            except SubPiso.DoesNotExist:
                                pass 

                        # Buscar/crear usuario externo con cédula limpia
                        usuario_externo = None
                        cedula = row.get('CEDULA', '').strip()
                        nombre = row.get('NOMBRE', '').strip()
                        telefono = row.get('TELEFONO', '').strip() 
                        
                        
                        
                        if nombre and cedula:
                            try:
                                usuario_externo, _ = UsuarioExterno.objects.update_or_create(
                                    documento=cedula,
                                    defaults={
                                        'nombre_completo': nombre.title(),
                                        'cargo': row.get('CARGO', '').title(),
                                        'tipo_documento': 'CC',
                                        'telefono': telefono if telefono else None 
                                    }
                                )
                                if not created and not usuario_externo.telefono and telefono:
                                    usuario_externo.telefono = telefono
                                    usuario_externo.save()
                            except Exception as e:
                                errors.append(f"Fila {row_num}: Error al procesar usuario - {str(e)}")
                                continue

                        # Procesar servicio
                        servicio = None
                        servicio_nombre = row.get('SERVICIO', '')
                        codigo_analitico = row.get('CODIGO_ANALITICO', '')

                        if es_portatil:
                            servicio_nombre = 'PORTATIL'
                            codigo_analitico = 'PORTATIL'
                        elif servicio_nombre and codigo_analitico and servicio_nombre != 'SIN ASIGNACION' and codigo_analitico != 'SIN ASIGNACION':
                            servicio, _ = Servicios.objects.get_or_create(
                                codigo_analitico=codigo_analitico,
                                defaults={
                                    'nombre': servicio_nombre,
                                    'color': '#FFFFFF'      
                                }
                            )
                            if servicio.nombre != servicio_nombre:
                                servicio.nombre = servicio_nombre
                                servicio.save()
                            if sede not in servicio.sedes.all():
                                servicio.sedes.add(sede)

                        # Buscar posición (modificado para no usar subpiso)
                        posicion = None
                        posicion_nombre = str(row.get('POSICION', '')).strip()
                        if posicion_nombre and piso and posicion_nombre != '-' and piso_raw != '-':
                            if posicion_nombre.isdigit():
                                posicion_nombre = posicion_nombre.zfill(4)
                            
                            # Buscar posición solo por piso, no por subpiso
                            posicion = Posicion.objects.filter(
                                nombre=posicion_nombre,
                                piso=piso,
                                piso__sede=sede
                            ).first()
                            
                            if not posicion and not es_portatil:
                                errors.append(f"Fila {row_num}: Posición {posicion_nombre} en piso {piso_raw} no existe")
                                continue
                            
                            if servicio and posicion and posicion.servicio != servicio:
                                posicion.servicio = servicio
                                posicion.save()

                        # Crear/actualizar dispositivo
                        dispositivo_data = {
                            'tipo': tipo_dispositivo,
                            'marca': row.get('FABRICANTE', 'DESCONOCIDO'),
                            'modelo': modelo,
                            'serial': serial or None,
                            'placa_cu': cu or None,
                            'sistema_operativo': row.get('SISTEMA_OPERATIVO', ''),
                            'procesador': row.get('PROCESADOR', ''),
                            'generacion': row.get('GENERACION', ''),
                            'capacidad_disco_duro': row.get('DISCO_DURO', ''),
                            'capacidad_memoria_ram': row.get('MEMORIA_RAM', ''),
                            'proveedor': row.get('PROVEEDOR', ''),
                            'estado_propiedad': row.get('ESTADO_PROVEEDOR', 'PROPIO'),
                            'razon_social': row.get('RAZON_SOCIAL', ''),
                            'ubicacion': row.get('UBICACION', 'SEDE'),
                            'estado': estado,
                            'observaciones': row.get('OBSERVACION', ''),
                            'regimen': row.get('REGIMEN', ''),
                            'piso': piso,
                            'subpiso': subpiso,
                            'tpm': tpm,
                            'sede': sede,
                            'estado_uso': 'DISPONIBLE',
                            'posicion': posicion
                        }

                        if not dispositivo_data['serial'] and not dispositivo_data['placa_cu']:
                            raise ValidationError("Se requiere al menos SERIAL o CU")

                        dispositivo = None
                        if serial:
                            dispositivo = Dispositivo.objects.filter(serial=serial).first()
                        elif cu:
                            dispositivo = Dispositivo.objects.filter(placa_cu=cu).first()

                        if dispositivo:
                            for key, value in dispositivo_data.items():
                                if value:
                                    setattr(dispositivo, key, value)
                            dispositivo.save()
                            updated += 1
                        else:
                            dispositivo = Dispositivo.objects.create(**dispositivo_data)
                            created += 1

                        # Asignar a posición
                        if posicion and not es_portatil:
                            if not posicion.dispositivos.filter(id=dispositivo.id).exists():
                                if posicion.dispositivos.count() < Posicion.MAX_DISPOSITIVOS:
                                    posicion.dispositivos.add(dispositivo)
                                else:
                                    errors.append(f"Fila {row_num}: Posición {posicion.nombre} ya tiene {Posicion.MAX_DISPOSITIVOS} dispositivos")

                        # Registrar en historial
                        cambios = {
                            k: [getattr(dispositivo, k, None), v] 
                            for k, v in dispositivo_data.items() 
                            if hasattr(Dispositivo, k) and getattr(dispositivo, k, None) != v
                        } if dispositivo.pk else dispositivo_data
                        
                        Historial.objects.create(
                            dispositivo=dispositivo,
                            usuario=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
                            cambios=cambios,
                            tipo_cambio=Historial.TipoCambio.MODIFICACION if dispositivo.pk else Historial.TipoCambio.CREACION,
                            modelo_afectado="Dispositivo",
                            instancia_id=dispositivo.id,
                            sede_nombre=sede.nombre
                        )

                        # Asignar a usuario externo
                        if usuario_externo:
                            asignacion_vigente = AsignacionDispositivo.objects.filter(
                                dispositivo=dispositivo,
                                estado='VIGENTE'
                            ).first()

                            if not asignacion_vigente or asignacion_vigente.usuario != usuario_externo:
                                if asignacion_vigente:
                                    asignacion_vigente.estado = 'DEVUELTO'
                                    asignacion_vigente.fecha_devolucion = timezone.now()
                                    asignacion_vigente.save()

                                ubicacion = 'CASA' if es_portatil else 'SEDE'
                                AsignacionDispositivo.objects.create(
                                    usuario=usuario_externo,
                                    dispositivo=dispositivo,
                                    estado='VIGENTE',
                                    ubicacion_asignada=ubicacion,
                                    asignado_por=request.user if hasattr(request, 'user') else None
                                )
                                dispositivo.estado_uso = 'EN_USO'
                                dispositivo.ubicacion = ubicacion
                                dispositivo.save()

                    except Exception as e:
                        error_msg = f'Fila {row_num}: Error al procesar - {str(e)}'
                        logger.error(error_msg, exc_info=True)
                        errors.append(error_msg)
                        continue

        result = {
            'message': 'Importación completada',
            'total': total_rows,
            'created': created,
            'updated': updated,
            'errors': errors if errors else None,
            'sede': sede.nombre
        }

        if errors:
            result['warning'] = f'Se encontraron {len(errors)} errores'

        return Response(result, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f'Error en importación: {str(e)}', exc_info=True)
        return Response({'error': f'Error en el servidor: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@permission_classes([AllowAny])
def subir_excel(request):
    if request.method == "POST" and request.FILES.get("archivo"):
        archivo = request.FILES["archivo"]
        return importar_excel(archivo)
    return JsonResponse({"error": "No se recibió ningún archivo"}, status=400)

@permission_classes([AllowAny])
def descargar_excel(request):
    return exportar_excel()

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.db import transaction
import time
import logging

logger = logging.getLogger(__name__)

class PosicionListCreateView(generics.ListCreateAPIView):
    queryset = Posicion.objects.all()
    serializer_class = PosicionSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            data = request.data.copy()
            
            logger.info(f"Creando posición con datos: {data}")

            # Verificar si ya existe una posición en la misma ubicación
            if "fila" in data and "columna" in data and "piso" in data:
                existing = Posicion.objects.filter(
                    fila=data["fila"],
                    columna=data["columna"],
                    piso=data["piso"]
                ).first()
                
                if existing:
                    return Response({
                        'error': f'Ya existe una posición en la fila {data["fila"]}, columna {data["columna"]} del piso {data["piso"]}'
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Procesar servicio
            if "servicio" in data and data["servicio"]:
                data["servicio_id"] = data["servicio"]
                del data["servicio"]

            # Validar y guardar
            serializer = self.get_serializer(data=data)
            if serializer.is_valid():
                try:
                    with transaction.atomic():
                        instance = serializer.save()
                        logger.info(f"Posición creada exitosamente: {instance.id}")
                        return Response(serializer.data, status=status.HTTP_201_CREATED)
                except Exception as e:
                    logger.error(f"Error al guardar posición: {str(e)}")
                    return Response({
                        'error': f'Error al guardar la posición: {str(e)}'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                logger.error(f"Errores de validación: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error inesperado en create: {str(e)}")
            return Response({
                'error': f'Error inesperado: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PosicionRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Posicion.objects.all()
    serializer_class = PosicionSerializer
    lookup_field = 'id'
    permission_classes = [AllowAny]

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            data = request.data.copy()
            
            logger.info(f"Actualizando posición {instance.id} con datos: {data}")

            # Procesar servicio
            if "servicio" in data:
                if data["servicio"]:
                    data["servicio_id"] = data["servicio"]
                else:
                    data["servicio_id"] = None
                del data["servicio"]

            # Validación de datos
            serializer = self.get_serializer(instance, data=data, partial=True)
            if serializer.is_valid():
                try:
                    with transaction.atomic():
                        updated_instance = serializer.save()
                        logger.info(f"Posición {instance.id} actualizada exitosamente")
                        return Response(serializer.data, status=status.HTTP_200_OK)
                except Exception as e:
                    logger.error(f"Error al actualizar posición {instance.id}: {str(e)}")
                    return Response({
                        'error': f'Error al actualizar la posición: {str(e)}'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                logger.error(f"Errores de validación en actualización: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error inesperado en update: {str(e)}")
            return Response({
                'error': f'Error inesperado: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            logger.info(f"Eliminando posición {instance.id}")
            
            with transaction.atomic():
                # Liberar dispositivos asociados
                for dispositivo in instance.dispositivos.all():
                    dispositivo.posicion = None
                    dispositivo.piso = None
                    dispositivo.save()
                
                instance.delete()
                logger.info(f"Posición {instance.id} eliminada exitosamente")
                return Response({
                    "message": "Posición eliminada correctamente"
                }, status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            logger.error(f"Error al eliminar posición: {str(e)}")
            return Response({
                'error': f'Error al eliminar la posición: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def get_colores_pisos(request):
    return Response({
        "colores": dict(Posicion.COLORES),
        "pisos": dict(Posicion.PISOS),
    })

class HistorialViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [AllowAny]
    queryset = Historial.objects.all().select_related('dispositivo', 'usuario')
    serializer_class = HistorialSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['tipo_cambio']
    search_fields = [
        'dispositivo__serial', 
        'dispositivo__modelo',
        'dispositivo__marca',
        'dispositivo__placa_cu',
        'usuario__nombre',
        'usuario__username',
        'usuario__email'
    ]
    ordering_fields = ['fecha_modificacion', 'fecha_creacion']
    ordering = ['-fecha_modificacion']  # Orden por defecto

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filtros adicionales
        fecha_inicio = self.request.query_params.get('fecha_inicio')
        fecha_fin = self.request.query_params.get('fecha_fin')
        dispositivo_id = self.request.query_params.get('dispositivo_id')
        tipo_cambio = self.request.query_params.get('tipo_cambio')
        try:
            if fecha_inicio:
                fecha_inicio_dt = datetime.strptime(fecha_inicio, '%Y-%m-%d')
                queryset = queryset.filter(fecha_modificacion__gte=fecha_inicio_dt)
                
            if fecha_fin:
                fecha_fin_dt = datetime.strptime(fecha_fin, '%Y-%m-%d') + timedelta(days=1)
                queryset = queryset.filter(fecha_modificacion__lte=fecha_fin_dt)
        except ValueError as e:
            pass
        if dispositivo_id:
            if dispositivo_id.isdigit():
                queryset = queryset.filter(dispositivo__id=dispositivo_id)
            else:
                queryset = queryset.filter(
                    Q(dispositivo__serial__icontains=dispositivo_id) |
                    Q(dispositivo__placa_cu__icontains=dispositivo_id) |
                    Q(dispositivo__modelo__icontains=dispositivo_id) |
                    Q(dispositivo__marca__icontains=dispositivo_id)
                )
                
        if tipo_cambio:
            queryset = queryset.filter(tipo_cambio=tipo_cambio)
            
        return queryset

    @action(detail=False, methods=['get'])
    def opciones_filtro(self, request):
        dispositivos = Dispositivo.objects.all().order_by('-id')[:100]
        
        return Response({
            'tipos_cambio': dict(Historial.TipoCambio.choices),
            'dispositivos': [
                {
                    'id': d.id,
                    'marca': d.marca,
                    'modelo': d.modelo,
                    'serial': d.serial,
                    'placa_cu': d.placa_cu
                } 
                for d in dispositivos
            ],
            'ordering_fields': self.ordering_fields,
            'search_fields': self.search_fields
        })


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def refresh_token_view(request):
    try:
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'error': 'Refresh token requerido'}, status=400)
            
        refresh = RefreshToken(refresh_token)
        new_access = str(refresh.access_token)
        
        return Response({
            'access': new_access,
            'refresh': str(refresh)
        }, status=200)
        
    except TokenError as e:
        return Response({'error': str(e)}, status=401)

        
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def dispositivos_por_sede(request):
    try:
        # Consulta corregida - usando 'dispositivos' en lugar de 'dispositivo'
        sedes_con_dispositivos = Sede.objects.annotate(
            total_dispositivos=Count('dispositivos')  # ¡Cambio importante aquí!
        ).values('nombre', 'total_dispositivos').order_by('nombre')

        response = Response({
            'success': True,
            'data': list(sedes_con_dispositivos)
        }, status=200)

        # Configuración CORS
        response["Access-Control-Allow-Origin"] = "http://localhost:3000"
        response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        
        return response

    except Exception as e:
        logger.error(f"Error en dispositivos_por_sede: {str(e)}", exc_info=True)
        return Response({
            'success': False,
            'error': "Error al procesar la solicitud"
        }, status=500)
        
def dispositivo_choices(request):
    return JsonResponse({
        'TIPOS_DISPOSITIVOS': Dispositivo.TIPOS_DISPOSITIVOS,
        'FABRICANTES': Dispositivo.FABRICANTES,
        'ESTADO_DISPOSITIVO': Dispositivo.ESTADO_DISPOSITIVO,
        'RAZONES_SOCIALES': Dispositivo.RAZONES_SOCIALES,
        'SISTEMAS_OPERATIVOS': Dispositivo.SISTEMAS_OPERATIVOS,
        'PROCESADORES': Dispositivo.PROCESADORES,
        'UBICACIONES': Dispositivo.UBICACIONES,
        'ESTADOS_PROPIEDAD': Dispositivo.ESTADOS_PROPIEDAD,
        'CAPACIDADES_DISCO_DURO': Dispositivo.CAPACIDADES_DISCO_DURO,
        'CAPACIDADES_MEMORIA_RAM': Dispositivo.CAPACIDADES_MEMORIA_RAM,
        'ESTADO_USO': Dispositivo.ESTADO_USO,
    })
    
    
    
    
# vistas para los movimientos
    
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def dispositivos_disponibles_para_movimiento(request, sede_id):
    """Obtiene dispositivos disponibles para mover en una sede específica"""
    try:
        dispositivos = Dispositivo.objects.filter(
            sede_id=sede_id,
            estado_uso='DISPONIBLE'  # Solo dispositivos disponibles
        ).values('id', 'serial', 'modelo', 'marca', 'posicion__nombre')
        
        return Response(dispositivos, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error al obtener dispositivos: {str(e)}")
        return Response(
            {"error": "Error al obtener dispositivos disponibles"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Mejorar el MovimientoViewSet
class MovimientoViewSet(viewsets.ModelViewSet):
    """
    ViewSet para gestionar movimientos de dispositivos entre posiciones.
    Incluye endpoints para:
    - Listar movimientos con filtros
    - Crear nuevos movimientos
    - Revertir movimientos
    - Obtener resumen estadístico
    """
    queryset = Movimiento.objects.select_related(
        'dispositivo',
        'posicion_origen',
        'posicion_destino',
        'encargado',
        'sede'
    ).all()
    serializer_class = MovimientoSerializer
    pagination_class = StandardPagination
    
    def get_queryset(self):
        """
        Filtra los movimientos según los parámetros de consulta:
        - dispositivo: ID del dispositivo
        - sede: ID de la sede
        - posicion: ID de posición (origen o destino)
        - fecha_inicio/fecha_fin: Rango de fechas
        - encargado: ID del usuario encargado
        """
        queryset = super().get_queryset()
        
        # Filtros básicos
        params = self.request.query_params
        
        if 'dispositivo' in params:
            queryset = queryset.filter(dispositivo__id=params['dispositivo'])
            
        if 'sede' in params:
            queryset = queryset.filter(sede__id=params['sede'])
            
        if 'posicion' in params:
            queryset = queryset.filter(
                Q(posicion_origen__id=params['posicion']) | 
                Q(posicion_destino__id=params['posicion'])
            )
            
        if 'encargado' in params:
            queryset = queryset.filter(encargado__id=params['encargado'])
            
        # Filtro por rango de fechas
        fecha_inicio = params.get('fecha_inicio')
        fecha_fin = params.get('fecha_fin')
        if fecha_inicio and fecha_fin:
            queryset = queryset.filter(
                fecha_movimiento__date__range=[fecha_inicio, fecha_fin]
            )
        elif fecha_inicio:
            queryset = queryset.filter(
                fecha_movimiento__date__gte=fecha_inicio
            )
        elif fecha_fin:
            queryset = queryset.filter(
                fecha_movimiento__date__lte=fecha_fin
            )
            
        return queryset.order_by('-fecha_movimiento')

    def list(self, request, *args, **kwargs):
        """
        Lista paginada de movimientos con capacidad de filtrado
        """
        try:
            return super().list(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error al listar movimientos: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error al recuperar movimientos"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def create(self, request, *args, **kwargs):
        """
        Crea un nuevo movimiento con validación básica
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            with transaction.atomic():
                movimiento = serializer.save()
                
                # Actualizar posición del dispositivo si hay destino
                pos_destino = movimiento.posicion_destino
                if pos_destino:
                    dispositivo = movimiento.dispositivo
                    dispositivo.posicion = pos_destino
                    dispositivo.save()
                    
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error al crear movimiento: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error al crear movimiento"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
            
    @permission_classes([AllowAny])
    @action(detail=True, methods=['GET', 'POST'])
    def confirmar_movimiento(self, request, pk=None):
        """
        Endpoint para confirmar un movimiento y aplicar los cambios a las posiciones
        """
        movimiento = self.get_object()
        
        if movimiento.confirmado:
            return Response(
                {"error": "Este movimiento ya fue confirmado"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        dispositivo = movimiento.dispositivo
        posicion_destino = movimiento.posicion_destino
        
        if not dispositivo:
            return Response(
                {"error": "Movimiento no tiene dispositivo asociado"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            with transaction.atomic():
                # 1. Remover de posición anterior si existe
                posicion_anterior = dispositivo.posicion
                if posicion_anterior:
                    posicion_anterior.dispositivos.remove(dispositivo)
                
                # 2. Agregar a nueva posición si existe
                if posicion_destino:
                    # Verificar límite de dispositivos
                    if posicion_destino.dispositivos.count() >= Posicion.MAX_DISPOSITIVOS:
                        return Response(
                            {"error": f"La posición destino ya tiene el máximo de {Posicion.MAX_DISPOSITIVOS} dispositivos"},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    posicion_destino.dispositivos.add(dispositivo)
                    dispositivo.posicion = posicion_destino
                    dispositivo.sede = posicion_destino.sede if posicion_destino.sede else movimiento.sede
                
                # 3. Si no hay posición destino, dejar el dispositivo sin posición
                else:
                    dispositivo.posicion = None
                
                dispositivo.save()
                
                # 4. Marcar movimiento como confirmado
                movimiento.confirmado = True
                movimiento.fecha_confirmacion = timezone.now()
                movimiento.save()
                
                # 5. Registrar en historial
                Historial.objects.create(
                    dispositivo=dispositivo,
                    usuario=request.user,
                    tipo_cambio=Historial.TipoCambio.MOVIMIENTO,
                    cambios={
                        "movimiento_id": movimiento.id,
                        "posicion_anterior": posicion_anterior.id if posicion_anterior else None,
                        "posicion_nueva": posicion_destino.id if posicion_destino else None
                    }
                )
                
                return Response(
                    {"message": "Movimiento confirmado y cambios aplicados"},
                    status=status.HTTP_200_OK
                )
                
        except Exception as e:
            logger.error(f"Error al confirmar movimiento: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error al confirmar movimiento"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['GET', 'POST'])
    @permission_classes([AllowAny])
    def crear_movimiento_completo(self, request):
        """
        Endpoint especializado para creación de movimientos con validaciones completas:
        - Verifica límite de dispositivos en posición destino
        - Registra en historial de cambios
        - Actualiza posición del dispositivo
        """
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            with transaction.atomic():
                # Validaciones adicionales
                dispositivo = serializer.validated_data['dispositivo']
                pos_destino = serializer.validated_data.get('posicion_destino')
                pos_origen = dispositivo.posicion
                
                # Verificar límite en posición destino
                if pos_destino and pos_destino.dispositivos.count() >= Posicion.MAX_DISPOSITIVOS:
                    return Response(
                        {"error": f"La posición destino ya tiene el máximo de {Posicion.MAX_DISPOSITIVOS} dispositivos"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Crear movimiento
                movimiento = serializer.save(encargado=request.user)
                
                # Actualizar posición del dispositivo si hay destino
                if pos_destino:
                    # Remover de posición anterior si existe
                    if pos_origen:
                        pos_origen.dispositivos.remove(dispositivo)
                    
                    # Agregar a nueva posición
                    pos_destino.dispositivos.add(dispositivo)
                    dispositivo.posicion = pos_destino
                    dispositivo.piso = pos_destino.piso
                    dispositivo.save()
                    
                    # Registrar en el historial
                    Historial.objects.create(
                        dispositivo=dispositivo,
                        usuario=request.user,
                        tipo_cambio=Historial.TipoCambio.MOVIMIENTO,
                        cambios={
                            "posicion_anterior": pos_origen.id if pos_origen else None,
                            "posicion_nueva": pos_destino.id,
                            "movimiento_id": movimiento.id
                        }
                    )
                
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            logger.error(f"Error al crear movimiento completo: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error interno al crear movimiento"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['GET', 'POST'])
    def revertir(self, request, pk=None):
        """
        Revertir un movimiento existente:
        1. Crea un movimiento inverso
        2. Devuelve el dispositivo a su posición original
        3. Actualiza el historial
        """
        movimiento = self.get_object()
        
        try:
            with transaction.atomic():
                # Verificar si se puede revertir
                if not movimiento.posicion_destino:
                    return Response(
                        {"error": "Este movimiento no tiene posición destino y no puede ser revertido"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Crear movimiento inverso
                nuevo_movimiento = Movimiento.objects.create(
                    dispositivo=movimiento.dispositivo,
                    posicion_origen=movimiento.posicion_destino,
                    posicion_destino=movimiento.posicion_origen,
                    encargado=request.user,
                    observacion=f"Reversión del movimiento #{movimiento.id}",
                    sede=movimiento.sede
                )
                
                # Actualizar posición del dispositivo
                dispositivo = movimiento.dispositivo
                
                # Remover de posición actual
                if dispositivo.posicion:
                    dispositivo.posicion.dispositivos.remove(dispositivo)
                
                # Agregar a posición original si existe
                if movimiento.posicion_origen:
                    movimiento.posicion_origen.dispositivos.add(dispositivo)
                    dispositivo.posicion = movimiento.posicion_origen
                    dispositivo.piso = movimiento.posicion_origen.piso
                    dispositivo.save()
                
                # Registrar en el historial
                Historial.objects.create(
                    dispositivo=dispositivo,
                    usuario=request.user,
                    tipo_cambio=Historial.TipoCambio.REVERSION,
                    cambios={
                        "movimiento_original": movimiento.id,
                        "movimiento_reversion": nuevo_movimiento.id,
                        "posicion_actual": dispositivo.posicion.id if dispositivo.posicion else None
                    }
                )
                
                serializer = self.get_serializer(nuevo_movimiento)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            logger.error(f"Error al revertir movimiento: {str(e)}", exc_info=True)
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['GET', 'POST'])
    def resumen(self, request):
        """
        Resumen estadístico de movimientos:
        - Agrupado por tipo de dispositivo y ubicación destino
        - Conteo total por cada combinación
        """
        try:
            queryset = self.filter_queryset(self.get_queryset())
            
            resumen = queryset.values(
                'dispositivo__tipo',
                'ubicacion_destino'
            ).annotate(
                total=Count('id')
            ).order_by('-total')
            
            return Response(resumen)
        except Exception as e:
            logger.error(f"Error al generar resumen: {str(e)}", exc_info=True)
            return Response(
                {"error": "Error al generar resumen de movimientos"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['GET', 'POST'])
    def opciones_filtro(self, request):
        """
        Devuelve opciones disponibles para filtrar movimientos:
        - Lista de dispositivos
        - Lista de ubicaciones
        - Lista de sedes
        """
        try:
            from .models import Ubicacion
            
            data = {
                'ubicaciones': dict(Ubicacion.UBICACIONES),
                'dispositivos': list(Dispositivo.objects.filter(
                    estado_uso='DISPONIBLE'
                ).values('id', 'marca', 'modelo', 'serial')),
                'sedes': list(Sede.objects.all().values('id', 'nombre'))
            }
            
            return Response(data)
            
        except Exception as e:
            logger.error(f"Error en opciones_filtro: {str(e)}")
            return Response(
                {'error': 'Error al obtener opciones de filtro'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
            
# vistas para registro de entradas y salidas de dispositivos
@api_view(['GET'])
@permission_classes([AllowAny])  # Puedes agregar permisos si es necesario
def movimientos_por_sede(request):
    sede_id = request.query_params.get('sede')
    
    try:
        # Query base para sedes con movimientos
        sedes_query = Sede.objects.annotate(
            total_movimientos=Count('movimiento')  # Relación inversa correcta
        )

        # Contar movimientos sin sede asignada
        movimientos_sin_sede = Movimiento.objects.filter(sede__isnull=True).count()

        # Aplicar filtros según parámetros
        if sede_id == "null":
            data = [{
                'nombre_sede': 'Sin sede asignada',
                'total_movimientos': movimientos_sin_sede
            }]
        elif sede_id:
            sede_id = int(sede_id)
            sedes_query = sedes_query.filter(id=sede_id)
            data = list(sedes_query.values('id', 'nombre', 'total_movimientos'))
            
            # Formatear datos para la gráfica de React
            data = [{
                'name': item['nombre'],
                'value': item['total_movimientos']
            } for item in data]
        else:
            # Todas las sedes más movimientos sin sede
            data = list(sedes_query.values('id', 'nombre', 'total_movimientos'))
            
            # Formatear datos para la gráfica de React
            data = [{
                'name': item['nombre'],
                'value': item['total_movimientos']
            } for item in data]
            
            # Agregar movimientos sin sede si existen
            if movimientos_sin_sede > 0:
                data.append({
                    'name': 'Sin sede asignada',
                    'value': movimientos_sin_sede
                })

        # Calcular totales
        total_movimientos = sum(item['value'] for item in data)
        total_sedes = len(data)

        return Response({
            'success': True,
            'data': data,
            'total_movimientos': total_movimientos,
            'total_sedes': total_sedes,
            'message': 'Datos de movimientos por sede obtenidos correctamente'
        }, status=status.HTTP_200_OK)

    except (ValueError, TypeError):
        return Response({
            'success': False,
            'error': 'ID de sede inválido',
            'message': 'El parámetro sede debe ser un número entero válido'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            'success': False,
            'error': str(e),
            'message': 'Error al obtener los movimientos por sede'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['GET'])
@permission_classes([AllowAny])
def gestion_usuarios_externos_completa(request):
    """Lista TODOS los usuarios externos para gestión administrativa"""
    try:
        usuarios = UsuarioExterno.objects.all().order_by('nombre_completo')
        print(f"[DEBUG] Total usuarios en DB: {usuarios.count()}")  # Debug en consola del servidor
        serializer = UsuarioExternoSerializer(usuarios, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'count': usuarios.count()
        }, status=status.HTTP_200_OK)
    except Exception as e:
        print(f"[ERROR] {str(e)}")  # Debug
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def usuario_externo_view(request):
    """
    GET: Lista todos los usuarios externos activos
    POST: Crea un nuevo usuario externo
    """
    print('Usuario autenticado:', request.user)  # Verifica en la consola del servidor
    print('Token recibido:', request.auth)  # Depuración
    if request.method == 'GET':
        usuarios = UsuarioExterno.objects.filter(activo=True).order_by('nombre_completo')
        serializer = UsuarioExternoSerializer(usuarios, many=True)
        return Response({
            'success': True,
            'data': serializer.data
        })

    elif request.method == 'POST':
        serializer = UsuarioExternoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'success': True,
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def usuario_externo_detail_view(request, usuario_id):
    """
    GET: Detalle de un usuario externo
    PUT: Actualiza un usuario externo
    DELETE: Desactiva un usuario externo (eliminación lógica)
    """
    usuario = get_object_or_404(UsuarioExterno, id=usuario_id)

    if request.method == 'GET':
        serializer = UsuarioExternoSerializer(usuario)
        return Response({
            'success': True,
            'data': serializer.data
        })

    elif request.method == 'PUT':
        serializer = UsuarioExternoSerializer(usuario, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'success': True,
                'data': serializer.data
            })
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        usuario.activo = False
        usuario.save()
        return Response({
            'success': True,
            'message': 'Usuario desactivado correctamente'
        }, status=status.HTTP_204_NO_CONTENT)
            


#VIEWS DE ASIGNACION DISPOSITIVO
@api_view(['GET'])
@permission_classes([AllowAny])
def asignaciones_dispositivos_list(request):
    """
    Lista asignaciones con filtros
    """
    try:
        queryset = AsignacionDispositivo.objects.select_related(
            'usuario', 
            'dispositivo',
            'asignado_por'
        ).all()
        
        # Filtros
        usuario_id = request.query_params.get('usuario_id')
        dispositivo_id = request.query_params.get('dispositivo_id')
        estado = request.query_params.get('estado')
        incluir_historicas = request.query_params.get('incluir_historicas', 'false').lower() == 'true'

        if usuario_id:
            queryset = queryset.filter(usuario_id=usuario_id)
        if dispositivo_id:
            queryset = queryset.filter(dispositivo_id=dispositivo_id)
        if estado:
            queryset = queryset.filter(estado=estado)
        if not incluir_historicas:
            queryset = queryset.filter(estado='VIGENTE')

        serializer = AsignacionDispositivoSerializer(queryset, many=True)
        
        return Response({
            "success": True,
            "data": serializer.data,
            "count": queryset.count()
        })

    except Exception as e:
        logger.exception(f"Error crítico al listar asignaciones. Usuario: {request.user.id}")  # Log completo
        return Response({
            "success": False,
            "error": str(e),
            "message": "Error al procesar la solicitud",
            "details": "Ocurrió un error interno al recuperar las asignaciones"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def crear_asignacion_dispositivo(request):
    try:
        data = request.data.copy()
        data['asignado_por'] = request.user.id
        
        # Obtener dispositivo
        dispositivo = Dispositivo.objects.get(id=data['dispositivo'])
        
        # Crear asignación sin validar estados (SOLO PARA PRUEBAS)
        serializer = AsignacionDispositivoCreateSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        asignacion = serializer.save()
        
        # Actualizar estado del dispositivo
        dispositivo.estado_uso = 'EN_USO'
        dispositivo.save()
        
        return Response(
            AsignacionDispositivoSerializer(asignacion).data, 
            status=status.HTTP_201_CREATED
        )

    except Exception as e:
        return Response(
            {"error": str(e)}, 
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def devolver_dispositivo(request, asignacion_id):
    """
    Marca una asignación como devuelta y libera el dispositivo
    """
    try:
        asignacion = AsignacionDispositivo.objects.get(id=asignacion_id, estado='VIGENTE')
        
        # Actualizar asignación
        asignacion.estado = 'DEVUELTO'
        asignacion.fecha_devolucion = timezone.now()
        asignacion.save()

        # Actualizar dispositivo
        dispositivo = asignacion.dispositivo
        dispositivo.estado_uso = 'DISPONIBLE'
        dispositivo.save()

        serializer = AsignacionDispositivoSerializer(asignacion)
        return Response(serializer.data)

    except AsignacionDispositivo.DoesNotExist:
        return Response(
            {"error": "Asignación no encontrada o ya fue devuelta"}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error al devolver dispositivo: {str(e)}")
        return Response(
            {"error": "Error al procesar devolución"}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    
    
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def actualizar_asignacion(request, asignacion_id):
    """
    Actualiza la ubicación de una asignación vigente
    """
    try:
        logger.info(f"Iniciando actualización para asignación {asignacion_id}")
        logger.info(f"Datos recibidos: {request.data}")
        logger.info(f"Usuario autenticado: {request.user.username}")

        # Obtener la asignación vigente
        asignacion = AsignacionDispositivo.objects.get(id=asignacion_id, estado='VIGENTE')
        logger.info(f"Asignación encontrada: {asignacion.id} - Ubicación actual: {asignacion.ubicacion_asignada}")

        # Validar datos
        if 'ubicacion_asignada' not in request.data:
            logger.error("Campo 'ubicacion_asignada' no proporcionado")
            return Response(
                {"success": False, "error": "El campo 'ubicacion_asignada' es requerido"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        nueva_ubicacion = request.data['ubicacion_asignada']
        logger.info(f"Nueva ubicación recibida: {nueva_ubicacion}")

        # Validar opciones de ubicación
        ubicaciones_validas = [choice[0] for choice in AsignacionDispositivo.UBICACIONES_ASIGNACION]
        logger.info(f"Ubicaciones válidas: {ubicaciones_validas}")
        
        if nueva_ubicacion not in ubicaciones_validas:
            logger.error(f"Ubicación no válida: {nueva_ubicacion}")
            return Response(
                {"success": False, "error": f"Ubicación no válida. Opciones: {ubicaciones_validas}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Actualizar
        asignacion.ubicacion_asignada = nueva_ubicacion
        asignacion.save()
        logger.info("Ubicación actualizada correctamente")

        return Response({
            "success": True,
            "message": "Ubicación actualizada correctamente",
            "data": {
                "id": asignacion.id,
                "ubicacion_actualizada": asignacion.ubicacion_asignada
            }
        })

    except AsignacionDispositivo.DoesNotExist:
        logger.error(f"Asignación {asignacion_id} no encontrada o no vigente")
        return Response(
            {"success": False, "error": "Asignación no encontrada o no está vigente"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.exception(f"Error crítico al actualizar ubicación. Detalles: {str(e)}")
        return Response(
            {"success": False, "error": f"Error interno al actualizar la ubicación: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def registrar_movimiento_dispositivo(request):
    try:
        data = request.data.copy()
        documento = data.get('documento')
        
        # Buscar usuario por documento
        try:
            usuario = UsuarioExterno.objects.get(documento=documento)
        except UsuarioExterno.DoesNotExist:
            return Response(
                {"error": "No se encontró usuario con ese documento"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Buscar asignaciones vigentes
        asignaciones = AsignacionDispositivo.objects.filter(
            usuario=usuario,
            estado='VIGENTE'
        ).select_related('dispositivo')
        
        if not asignaciones.exists():
            return Response(
                {"error": "El usuario no tiene dispositivos asignados actualmente"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # MODIFICACIÓN PRINCIPAL: Siempre usar la primera asignación
        asignacion = asignaciones.first()
        
        # Crear el registro de movimiento (las validaciones están en el serializer)
        movimiento_data = {
            'asignacion': asignacion.id,
            'tipo': data['tipo_movimiento'],
            'observaciones': data.get('observaciones', ''),
            'registrado_por': request.user.id
        }
        
        serializer = RegistroMovimientoDispositivoSerializer(data=movimiento_data)
        serializer.is_valid(raise_exception=True)
        registro = serializer.save()
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)
        
    except ValidationError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def buscar_usuario_dispositivo(request):
    documento = request.data.get('documento')
    if not documento:
        return Response({"error": "Documento requerido"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        usuario = UsuarioExterno.objects.get(documento=documento)
    except UsuarioExterno.DoesNotExist:
        return Response({"error": "No se encontró usuario con ese documento"}, status=status.HTTP_404_NOT_FOUND)

    asignaciones = AsignacionDispositivo.objects.filter(
        usuario=usuario,
        estado='VIGENTE'
    ).select_related('dispositivo')

    if not asignaciones.exists():
        return Response(
            {"error": "El usuario no tiene dispositivos asignados actualmente"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Verificar si el usuario ya está dentro (tiene ENTRADA sin SALIDA)
    usuario_ya_dentro = False
    asignaciones_con_info = []
    
    for asignacion in asignaciones:
        ultimo_movimiento = RegistroMovimientoDispositivo.objects.filter(
            asignacion=asignacion
        ).order_by('-fecha', '-hora').first()
        
        # Agregar estado actual a cada asignación
        estado_actual = "Dentro" if ultimo_movimiento and ultimo_movimiento.tipo == 'ENTRADA' else "Fuera"
        
        asignacion_data = AsignacionDispositivoSerializer(asignacion).data
        asignacion_data['estado_actual'] = estado_actual
        
        asignaciones_con_info.append(asignacion_data)
        
        if estado_actual == "Dentro":
            usuario_ya_dentro = True

    serializer = AsignacionDispositivoSerializer(asignaciones, many=True)
    return Response({
        "usuario_info": {
            "nombre": usuario.nombre_completo,
            "documento": f"{usuario.get_tipo_documento_display()} {usuario.documento}",
            "cargo": usuario.cargo
        },
        "asignaciones": asignaciones_con_info,
        "usuario_ya_dentro": usuario_ya_dentro
    })


class HistorialPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'per_page'
    max_page_size = 100

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def historial_movimientos(request):
    queryset = RegistroMovimientoDispositivo.objects.all().order_by('-fecha', '-hora')
     
    # Filtros
    tipo = request.query_params.get('tipo', None)
    documento = request.query_params.get('documento', None)
    fecha_inicio = request.query_params.get('fechaInicio', None)
    fecha_fin = request.query_params.get('fechaFin', None)
    
    if tipo:
        queryset = queryset.filter(tipo=tipo)
    if documento:
        queryset = queryset.filter(asignacion__usuario__documento__icontains=documento)
    if fecha_inicio:
        queryset = queryset.filter(fecha__gte=fecha_inicio)
    if fecha_fin:
        queryset = queryset.filter(fecha__lte=fecha_fin)
    
    paginator = HistorialPagination()
    result_page = paginator.paginate_queryset(queryset, request)
    serializer = RegistroMovimientoDispositivoSerializer(result_page, many=True)
    
    return paginator.get_paginated_response(serializer.data)



# correo de usuario externo
# views.py
# views.py
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework.decorators import api_view, permission_classes # type: ignore
from rest_framework.permissions import IsAuthenticated # type: ignore
from rest_framework.response import Response # type: ignore
from django.utils import timezone
from django.conf import settings

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enviar_correo_visitante(request):
    try:
        visitante = request.data.get('visitante', {})
        
        # Establecer destinatario fijo
        destinatario = 'ltllanoso@emergiacc.com'
        
        # Renderizar plantilla HTML
        html_content = render_to_string('emails/informacion_visitante.html', {
            'visitante': visitante,
            'fecha': timezone.now().strftime("%d/%m/%Y %H:%M"),
            'solicitante': request.user.get_full_name() or request.user.username
        })
        
        # Crear versión de texto plano
        text_content = strip_tags(html_content)
        
        # Configurar email
        email = EmailMultiAlternatives(
            subject=f"Información de Usuario con dispositivo asignado: {visitante.get('nombre_completo', 'Sin nombre')}",
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[destinatario],
            reply_to=[settings.DEFAULT_FROM_EMAIL],
        )
        email.attach_alternative(html_content, "text/html")
        
        # Enviar email
        email.send()
        
        return Response({'status': 'success', 'message': 'Correo enviado correctamente'})
    
    except Exception as e:
        return Response({'status': 'error', 'error': str(e)}, status=500)



from django.http import JsonResponse
from .models import Dispositivo

def dispositivo_choices_view(request):
    return JsonResponse({
        'TIPOS_DISPOSITIVOS': Dispositivo.TIPOS_DISPOSITIVOS,
        'ESTADO_DISPOSITIVO': Dispositivo.ESTADO_DISPOSITIVO,
        'ESTADO_USO': Dispositivo.ESTADO_USO,
        'ESTADOS_PROPIEDAD': Dispositivo.ESTADOS_PROPIEDAD,
    })
    
    
from rest_framework import viewsets, generics, status # type: ignore
from rest_framework.response import Response # type: ignore
from rest_framework.decorators import permission_classes, action # type: ignore
from rest_framework.permissions import AllowAny # type: ignore
from .models import Piso, SubPiso
from .serializers import PisoSerializer, SubPisoSerializer
from django.db.models import Count
from django.core.exceptions import ValidationError

@permission_classes([AllowAny])
class PisoViewSet(viewsets.ModelViewSet):
    queryset = Piso.objects.select_related('sede').all()
    serializer_class = PisoSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        sede_id = self.request.query_params.get('sede_id')
        if sede_id:
            queryset = queryset.filter(sede_id=sede_id)
        return queryset.order_by('orden')

    def perform_destroy(self, instance):
        if instance.subpisos.exists():
            return Response(
                {"error": "No se puede eliminar el piso porque tiene subpisos asociados."},
                status=status.HTTP_400_BAD_REQUEST
            )
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['get'])
    def subpisos(self, request, pk=None):
        piso = self.get_object()
        subpisos = piso.subpisos.all().order_by('orden')
        serializer = SubPisoSerializer(subpisos, many=True)
        return Response(serializer.data)

@permission_classes([AllowAny])
class SubPisoViewSet(viewsets.ModelViewSet):
    queryset = SubPiso.objects.select_related('piso_padre', 'sede').all()
    serializer_class = SubPisoSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        piso_id = self.request.query_params.get('piso_id')
        sede_id = self.request.query_params.get('sede_id')
        
        if piso_id:
            queryset = queryset.filter(piso_padre_id=piso_id)
        elif sede_id:
            queryset = queryset.filter(sede_id=sede_id)
            
        return queryset.order_by('orden')

    def perform_create(self, serializer):
        try:
            serializer.save()
        except ValidationError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
            
            
@api_view(['GET'])
@permission_classes([AllowAny])
def posiciones_para_movimientos(request):
    """Obtiene posiciones filtradas por sede y piso para movimientos"""
    piso_id = request.query_params.get('piso')
    sede_id = request.query_params.get('sede')
    
    print(f"Received request with piso_id: {piso_id}, sede_id: {sede_id}")  # Debug print
    
    if not piso_id or not sede_id:
        return Response(
            {"error": "Se requieren los parámetros piso y sede"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Convert to integers
        piso_id = int(piso_id)
        sede_id = int(sede_id)
        
        # Verify piso belongs to sede
        piso_exists = Piso.objects.filter(id=piso_id, sede_id=sede_id).exists()
        if not piso_exists:
            return Response(
                {"error": "El piso no pertenece a la sede especificada"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Get positions with related data
        posiciones = Posicion.objects.filter(
            piso_id=piso_id,
            sede_id=sede_id
        ).select_related('piso', 'sede').prefetch_related('dispositivos')
        
        print(f"Found {posiciones.count()} positions")  # Debug print
        
        serializer = PosicionSerializer(posiciones, many=True)
        return Response(serializer.data)
        
    except ValueError:
        return Response(
            {"error": "Los parámetros piso y sede deben ser números válidos"},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        print(f"Error: {str(e)}")  # Debug print
        return Response(
            {"error": "Error al obtener posiciones"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        
@api_view(['GET'])
@permission_classes([AllowAny])
def dispositivos_por_posicion(request, posicion_id):
    """Obtiene dispositivos disponibles en una posición específica"""
    try:
        # Verificar que la posición existe
        posicion = Posicion.objects.filter(id=posicion_id).first()
        if not posicion:
            return Response(
                {"error": "Posición no encontrada"},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Obtener dispositivos con filtros estrictos
        dispositivos = Dispositivo.objects.filter(
            posicion_id=posicion_id,
            estado_uso='DISPONIBLE'
        ).select_related('posicion')
        
        serializer = DispositivoSerializer(dispositivos, many=True)
        return Response(serializer.data)
        
    except Exception as e:
        logger.error(f"Error en dispositivos_por_posicion: {str(e)}")
        return Response(
            {"error": "Error al obtener dispositivos"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def posiciones_por_sede_view(request, sede_id):
    try:
        # Validar que el ID sea un número entero
        try:
            sede_id_int = int(sede_id)
            if sede_id_int <= 0:
                raise ValueError("El ID debe ser positivo")
        except ValueError:
            return Response(
                {"error": "El ID de sede debe ser un número entero positivo"},
                status=status.HTTP_400_BAD_REQUEST
            )
        posiciones = Posicion.objects.filter(sede_id=sede_id_int)\
            .select_related('sede')\
            .only('id', 'nombre', 'piso', 'sede')
    
        if not posiciones.exists():
            return Response(
                {"warning": f"No se encontraron posiciones para la sede ID {sede_id}"},
                status=status.HTTP_200_OK
            )
        return Response([{
            'id': p.id,
            'nombre': p.nombre,
            'piso': p.piso,
            'sede_id': p.sede.id if p.sede else None,
            'sede_nombre': p.sede.nombre if p.sede else 'Sin sede'
        } for p in posiciones])
        
    except Exception as e:
        logger.error(f"Error al obtener posiciones para sede {sede_id}: {str(e)}", exc_info=True)
        return Response(
            {"error": "Error interno al obtener posiciones"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 