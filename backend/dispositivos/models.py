from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
import re
from colorfield.fields import ColorField # type: ignore
from django.utils.translation import gettext_lazy as _
from django.contrib.postgres.fields import JSONField
from django.db.models.signals import post_save, pre_save, post_delete
from django.db import transaction
from django.contrib.auth.signals import user_logged_in
from django.utils.timezone import now, timedelta
from django.utils import timezone
import logging
from django.contrib.auth import get_user
from django.db.models.signals import pre_delete
import random

class Sede(models.Model):
    nombre = models.CharField(max_length=100, unique=True)
    ciudad = models.CharField(max_length=100)
    direccion = models.TextField()

    def __str__(self):
        return f"{self.nombre} - {self.ciudad}"

    class Meta:
        verbose_name = "Sede"
        verbose_name_plural = "Sedes"


class Piso(models.Model):
    """Modelo para representar los pisos principales de cada sede"""
    nombre = models.CharField(max_length=50)
    sede = models.ForeignKey(Sede, on_delete=models.CASCADE, related_name="pisos")
    orden = models.PositiveIntegerField(default=0, help_text="Orden de visualización")
    es_principal = models.BooleanField(default=True, help_text="Indica si es un piso principal o un subpiso")

    def __str__(self):
        return f"{self.nombre} - {self.sede.nombre}"

    class Meta:
        verbose_name = "Piso"
        verbose_name_plural = "Pisos"
        unique_together = [('sede', 'nombre')]
        ordering = ['sede', 'orden']


class SubPiso(models.Model):
    """Modelo para representar subpisos (antes sectores) que pertenecen a un piso principal"""
    nombre = models.CharField(max_length=50)
    piso_padre = models.ForeignKey(Piso, on_delete=models.CASCADE, related_name="subpisos", limit_choices_to={'es_principal': True})
    descripcion = models.TextField(blank=True, null=True)
    orden = models.PositiveIntegerField(default=0)
    sede = models.ForeignKey(Sede, on_delete=models.CASCADE, related_name="subpisos", editable=False, null=True, blank=True)  # Cambio importante aquí

    def __str__(self):
        return f"{self.nombre} - {self.piso_padre.nombre}"

    def clean(self):
        # Asignar automáticamente la sede del piso padre
        if self.piso_padre:
            self.sede = self.piso_padre.sede
        
        super().clean()  # Importante llamar al clean() padre

    def save(self, *args, **kwargs):
        # Asegurar que la sede esté establecida antes de guardar
        if not self.sede and self.piso_padre:
            self.sede = self.piso_padre.sede
        
        if not self.sede:
            raise ValidationError("No se puede guardar un SubPiso sin sede asignada")
        
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "SubPiso"
        verbose_name_plural = "SubPisos"
        unique_together = [('piso_padre', 'nombre')]
        ordering = ['piso_padre', 'orden']


class RolUser(AbstractUser):
    ROLES_CHOICES = [
        ('admin', 'Administrador'),
        ('coordinador', 'Coordinador'),
        ('celador', 'Celador'),
        ('seguridad', 'Seguridad'),
    ]
    
    rol = models.CharField(max_length=15, choices=ROLES_CHOICES, default='admin')
    nombre = models.CharField("Nombre completo", max_length=150, blank=True, null=True)
    last_activity = models.DateTimeField(default=timezone.now)
    celular = models.CharField(
        "Celular",
        max_length=15,
        blank=True,
        null=True,
        validators=[RegexValidator(regex=r'^\+?\d{7,15}$', message="Número de celular inválido")]
    )

    documento = models.CharField(
        "Documento de identificación",
        max_length=50,
        blank=True,
        null=True,
        unique=True
    )

    email = models.EmailField("Correo electrónico")

    sedes = models.ManyToManyField('Sede', blank=True, related_name='usuarios_asignados')

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_set',
        blank=True,
        help_text='Los grupos a los que pertenece este usuario.',
        related_query_name='custom_user',
    )
    
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_set',
        blank=True,
        help_text='Permisos específicos para este usuario.',
        related_query_name='custom_user',
    )

    def clean(self):
        if self.email:
            self.email = self.email.lower().strip()
        
        if self.celular and not re.match(r'^\+?\d{7,15}$', self.celular):
            raise ValidationError({
                'celular': "El número de celular debe ser un número válido con 7 a 15 dígitos, y puede incluir un signo '+' al principio."
            })

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.nombre} ({self.username})" if self.nombre else self.username

    class Meta:
        verbose_name = "Usuario"
        verbose_name_plural = "Usuarios"
        ordering = ['id']


from django.db import models
import random

class Servicios(models.Model):
    nombre = models.CharField(max_length=100)
    codigo_analitico = models.CharField(max_length=255, null=True, blank=True, unique=True)
    sedes = models.ManyToManyField('Sede', related_name="servicios")
    color = ColorField(default="#FFFFFF")

    @classmethod
    def generar_color_unico(cls):
        """Genera un color hexadecimal aleatorio que no exista en los servicios actuales"""
        while True:
            # Generar un color aleatorio en formato hexadecimal
            color = "#{:06x}".format(random.randint(0, 0xFFFFFF)).upper()
            
            # Verificar que no exista ya este color
            if not cls.objects.filter(color=color).exists():
                return color

    def save(self, *args, **kwargs):
        # Si es un nuevo servicio y no se especificó color, generar uno único
        if not self.pk and self.color == "#FFFFFF":
            self.color = self.generar_color_unico()        
        
        # Asegurar que el color de fuente tenga suficiente contraste
        if self.color:
            try:
                # Simple lógica para determinar color de fuente basado en luminosidad
                # Añadido manejo de errores para valores no hexadecimales
                r = int(self.color[1:3], 16) if len(self.color) >= 3 else 255
                g = int(self.color[3:5], 16) if len(self.color) >= 5 else 255
                b = int(self.color[5:7], 16) if len(self.color) >= 7 else 255
                luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
                self.colorFuente = "#000000" if luminance > 0.5 else "#FFFFFF"
            except (ValueError, AttributeError):
                # Si hay error en la conversión, usar valores por defecto
                self.colorFuente = "#000000"
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.nombre} ({self.codigo_analitico})"

    class Meta:
        verbose_name = "Servicios"
        verbose_name_plural = "Servicios"


from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import pre_delete
from django.dispatch import receiver

class Posicion(models.Model):
    ESTADOS = [
        ('disponible', 'Disponible'),
        ('ocupado', 'Ocupado'),
        ('reservado', 'Reservado'),
        ('inactivo', 'Inactivo'),
    ]

    MAX_DISPOSITIVOS = 5

    nombre = models.CharField(max_length=100, blank=True, null=True)
    tipo = models.CharField(max_length=50, blank=True, null=True)
    estado = models.CharField(max_length=50, choices=ESTADOS, default='disponible')
    detalles = models.TextField(blank=True, null=True)
    fila = models.IntegerField()
    columna = models.CharField(max_length=5)
    color = models.CharField(max_length=20, default='#FFFFFF')
    colorFuente = models.CharField(max_length=20, default='#000000')
    colorOriginal = models.CharField(max_length=50, blank=True, null=True)
    borde = models.BooleanField(default=True)
    bordeDoble = models.BooleanField(default=False)
    bordeDetalle = models.JSONField(default=dict)
    piso = models.ForeignKey('Piso', on_delete=models.CASCADE, null=True, blank=True)
    subpiso = models.ForeignKey('SubPiso', on_delete=models.SET_NULL, null=True, blank=True)
    servicio = models.ForeignKey(
        'Servicios', 
        on_delete=models.SET_NULL, 
        related_name="posiciones", 
        null=True, 
        blank=True
    )
    dispositivos = models.ManyToManyField(
        'Dispositivo', 
        related_name='posiciones', 
        blank=True
    )
    mergedCells = models.JSONField(default=list)

    def __str__(self):
        location = self.piso.nombre if self.piso else "Sin piso"
        sede_name = self.piso.sede.nombre if self.piso and self.piso.sede else "Sin sede"
        return f"{self.nombre or 'Posición'} - {location} ({sede_name})"

    def clean(self):
        """Validaciones adicionales"""
        if self.fila < 1:
            raise ValidationError("La fila debe ser un número positivo.")
        
        if not str(self.columna).isalpha():
            raise ValidationError("La columna debe contener solo letras.")

        if not self.piso:
            raise ValidationError("Debe asignar un piso a la posición.")

        # Validación de cantidad máxima de dispositivos
        if self.pk and self.dispositivos.count() > self.MAX_DISPOSITIVOS:
            raise ValidationError(
                f"Una posición no puede tener más de {self.MAX_DISPOSITIVOS} dispositivos."
            )

    def save(self, *args, **kwargs):
        """Personalización del método save"""
        save_dispositivos = False
        dispositivos_temp = None

        # Manejo de dispositivos temporales para nuevas posiciones
        if not self.pk and hasattr(self, '_dispositivos_temp'):
            dispositivos_temp = self._dispositivos_temp
            save_dispositivos = True
            delattr(self, '_dispositivos_temp')

        # Actualización de colores cuando cambia el servicio
        if self.servicio_id is None and 'servicio' in kwargs.get('update_fields', []):
            self.color = "#FFFFFF"
            self.colorFuente = "#000000"
            if 'update_fields' in kwargs:
                if 'color' not in kwargs['update_fields']:
                    kwargs['update_fields'].append('color')
                if 'colorFuente' not in kwargs['update_fields']:
                    kwargs['update_fields'].append('colorFuente')

        if self.servicio_id and (not self.pk or 'servicio' in kwargs.get('update_fields', [])):
            self.color = self.servicio.color
            self.colorFuente = self.servicio.colorFuente if hasattr(self.servicio, 'colorFuente') else '#000000'
            if 'update_fields' in kwargs:
                if 'color' not in kwargs['update_fields']:
                    kwargs['update_fields'].append('color')
                if 'colorFuente' not in kwargs['update_fields']:
                    kwargs['update_fields'].append('colorFuente')

        super().save(*args, **kwargs)

        # Asignar dispositivos después de guardar si es una nueva posición
        if save_dispositivos and dispositivos_temp:
            self.dispositivos.set(dispositivos_temp)

        # Validación final de cantidad de dispositivos
        if self.dispositivos.count() > self.MAX_DISPOSITIVOS:
            raise ValidationError(
                f"Una posición no puede tener más de {self.MAX_DISPOSITIVOS} dispositivos."
            )

    @property
    def sede(self):
        """Propiedad para acceder a la sede a través del piso"""
        return self.piso.sede if self.piso else None

    def cantidad_dispositivos(self):
        """Método para obtener la cantidad de dispositivos"""
        return self.dispositivos.count()

    class Meta:
        verbose_name = "Posición"
        verbose_name_plural = "Posiciones"
        unique_together = ('fila', 'columna', 'piso')
        ordering = ['piso', 'fila', 'columna']

@receiver(pre_delete, sender='dispositivos.Servicios')
def handle_servicio_delete(sender, instance, **kwargs):
    """
    Signal handler para actualizar posiciones cuando se elimina un servicio
    """
    from .models import Posicion
    
    Posicion.objects.filter(servicio=instance).update(
        servicio=None,
        color="#FFFFFF",
        colorFuente="#000000"
    )
    
class Dispositivo(models.Model):
    TIPOS_DISPOSITIVOS = [
        ('COMPUTADOR', 'Computador'),
        ('DESKTOP', 'Desktop'),
        ('MONITOR', 'Monitor'),
        ('TABLET', 'Tablet'),
        ('MOVIL', 'Celular'),
        ('HP_PRODISPLAY_P201', 'HP ProDisplay P201'),
        ('PORTATIL', 'Portátil'),
        ('TODO_EN_UNO', 'Todo en uno'),
    ]

    ESTADO_DISPOSITIVO = [
        ('BUENO', 'Bueno'),
        ('BODEGA_CN', 'Bodega CN'),
        ('BODEGA', 'Bodega'),
        ('MALA', 'Mala'),
        ('MALO', 'Malo'),
        ('PENDIENTE_BAJA', 'Pendiente/Baja'),
        ('PENDIENTE_ROBADA', 'Pendiente/Robada'),
        ('PERDIDO_ROBADO', 'Perdido/Robado'),
        ('REPARAR', 'Reparar'),
        ('REPARAR_BAJA', 'Reparar/Baja'),
        ('SEDE', 'Sede'),
        ('STOCK', 'Stock'),
    ]

    ESTADOS_PROPIEDAD = [
        ('PROPIO', 'Propio'),
        ('ARRENDADO', 'Arrendado'),
        ('DONADO', 'Donado'),
        ('COMPRADO', 'Comprado'),
        ('PRESTAMO', 'Préstamo'),
        ('RECUPERADO_COMPRADO', 'Recuperado/Comprado'),
        ('OTRO', 'Otro'),
        ('ALQUILADO', 'Alquilado'),
    ]

    ESTADO_USO = [
        ('DISPONIBLE', 'Disponible'),
        ('EN_USO', 'En uso'),
        ('INHABILITADO', 'Inhabilitado'),
    ]

    tipo = models.CharField(max_length=100, choices=TIPOS_DISPOSITIVOS)
    marca = models.CharField(max_length=100, db_index=True)
    modelo = models.CharField(max_length=100, db_index=True)
    serial = models.CharField(max_length=100, unique=True, db_index=True, null=True, blank=True)
    placa_cu = models.CharField(max_length=1000, null=True, blank=True)
    sistema_operativo = models.CharField(max_length=100, null=True, blank=True)
    procesador = models.CharField(max_length=100, null=True, blank=True)
    generacion = models.CharField(max_length=100, null=True, blank=True)
    capacidad_disco_duro = models.CharField(max_length=100, null=True, blank=True)
    capacidad_memoria_ram = models.CharField(max_length=100, null=True, blank=True)
    proveedor = models.CharField(max_length=100, null=True, blank=True)
    estado_propiedad = models.CharField(max_length=100, choices=ESTADOS_PROPIEDAD, null=True, blank=True)
    razon_social = models.CharField(max_length=100, null=True, blank=True)
    ubicacion = models.CharField(max_length=100, db_index=True)
    estado = models.CharField(max_length=100, choices=ESTADO_DISPOSITIVO, null=True, blank=True)
    estado_uso = models.CharField(max_length=100, choices=ESTADO_USO, blank=True, default='DISPONIBLE')
    regimen = models.CharField(max_length=100, null=True, blank=True)
    tpm = models.CharField(max_length=50, null=True, blank=True)
    observaciones = models.TextField(max_length=500, null=True, blank=True, verbose_name="Observaciones adicionales")
    subpiso = models.ForeignKey('SubPiso', on_delete=models.SET_NULL, null=True, blank=True, related_name='dispositivos_subpiso')
    piso = models.ForeignKey('Piso', on_delete=models.SET_NULL, null=True, blank=True, related_name='dispositivos_piso')
    sede = models.ForeignKey('Sede', on_delete=models.SET_NULL, null=True, blank=True, related_name="dispositivos", db_index=True)
    posicion = models.ForeignKey('Posicion', on_delete=models.SET_NULL, null=True, blank=True, related_name='dispositivos_relacionados')

    def __str__(self):
        return f"{self.tipo} {self.marca} {self.modelo} - {self.serial if self.serial else 'Sin serial'}"

    def clean(self):
        # Validación para asegurar que la sede del dispositivo coincida con la sede de la posición
        if self.posicion and self.sede and self.posicion.sede != self.sede:
            raise ValidationError(
                f"La posición seleccionada pertenece a la sede {self.posicion.sede.nombre}, "
                f"pero el dispositivo está asignado a la sede {self.sede.nombre}. "
                "Deben coincidir."
            )
        
        # Validar que el subpiso pertenezca al piso si ambos están definidos
        if self.subpiso and self.piso and self.subpiso.piso_padre != self.piso:
            raise ValidationError(
                f"El subpiso seleccionado pertenece al piso {self.subpiso.piso_padre.nombre}, "
                f"pero el dispositivo está asignado al piso {self.piso.nombre}."
            )
            
        # Validar que el piso pertenezca a la sede si ambos están definidos
        if self.piso and self.sede and self.piso.sede != self.sede:
            raise ValidationError(
                f"El piso seleccionado pertenece a la sede {self.piso.sede.nombre}, "
                f"pero el dispositivo está asignado a la sede {self.sede.nombre}."
            )
        
        # Validación para asegurar que la posición no tenga demasiados dispositivos
        if self.posicion and self.posicion.dispositivos.count() >= Posicion.MAX_DISPOSITIVOS:
            raise ValidationError(
                f"Esta posición ya tiene el máximo de {Posicion.MAX_DISPOSITIVOS} dispositivos asignados."
            )

    def save(self, *args, **kwargs):
        # Actualizar relaciones automáticamente
        if self.posicion:
            if not self.sede:
                self.sede = self.posicion.sede
            if not self.piso and self.posicion.piso:
                self.piso = self.posicion.piso
            if not self.subpiso and self.posicion.subpiso:
                self.subpiso = self.posicion.subpiso
            
        if self.subpiso and not self.piso:
            self.piso = self.subpiso.piso_padre
        if self.piso and not self.sede:
            self.sede = self.piso.sede
            
        self.clean()
        super().save(*args, **kwargs)

    def is_operativo(self):
        return self.estado_uso == 'EN_USO' and self.estado == 'BUENO'

    class Meta:
        verbose_name = "Dispositivo"
        verbose_name_plural = "Dispositivos"

class Historial(models.Model):
    class TipoCambio(models.TextChoices):  
        CREACION = 'CREACION', _('Creación de dispositivo')
        MODIFICACION = 'MODIFICACION', _('Modificación de datos')
        MOVIMIENTO = 'MOVIMIENTO', _('Movimiento registrado')
        LOGIN = 'LOGIN', _('Inicio de sesión')
        OTRO = 'OTRO', _('Otro')
        ELIMINACION = 'ELIMINACION', 'Eliminación' 

    dispositivo = models.ForeignKey('Dispositivo', on_delete=models.CASCADE, related_name='historial', null=True, blank=True)
    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    fecha_modificacion = models.DateTimeField(default=timezone.now)
    cambios = models.JSONField(null=True, blank=True)
    tipo_cambio = models.CharField(max_length=20, choices=TipoCambio.choices, default=TipoCambio.OTRO)
    modelo_afectado = models.CharField(max_length=100, null=True, blank=True)
    instancia_id = models.PositiveIntegerField(null=True, blank=True)
    sede_nombre = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return f"{self.get_tipo_cambio_display()} - {self.fecha_modificacion}"

    class Meta:
        ordering = ['-fecha_modificacion']
        verbose_name = "Historial"
        verbose_name_plural = "Historiales"


from django.db import models # type: ignore
from django.conf import settings # type: ignore
from django.core.exceptions import ValidationError # type: ignore
from django.db.models.signals import pre_save, post_save # type: ignore
from django.dispatch import receiver # type: ignore
from django.db import transaction # type: ignore
import logging

logger = logging.getLogger(__name__)
class Movimiento(models.Model):
    UBICACIONES = (
        ('BODEGA', 'Bodega'),
        ('SEDE', 'Sede'),
        ('REPARACION', 'Reparación'),
        ('BAJA', 'Baja'),
        ('OTRO', 'Otro'),
    )
    
    dispositivo = models.ForeignKey(
        'Dispositivo',
        on_delete=models.CASCADE,
        related_name='movimientos'
    )
    encargado = models.ForeignKey(
        'RolUser',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='movimientos_realizados'
    )
    fecha_movimiento = models.DateTimeField(auto_now_add=True)
    posicion_origen = models.ForeignKey(
        'Posicion',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='movimientos_salida'
    )
    posicion_destino = models.ForeignKey(
        'Posicion',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='movimientos_entrada'
    )
    ubicacion_origen = models.CharField(
        max_length=20,
        choices=UBICACIONES,
        null=True,
        blank=True
    )
    ubicacion_destino = models.CharField(
        max_length=20,
        choices=UBICACIONES,
        null=True,
        blank=True
    )
    observacion = models.TextField(blank=True)
    sede = models.ForeignKey(
        'Sede',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    
    confirmado = models.BooleanField(default=False)
    fecha_confirmacion = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-fecha_movimiento']
        verbose_name = 'Movimiento'
        verbose_name_plural = 'Movimientos'
        indexes = [
            models.Index(fields=['fecha_movimiento']),
            models.Index(fields=['dispositivo']),
            models.Index(fields=['encargado']),
        ]

    def __str__(self):
        return f"Movimiento #{self.id} - {self.dispositivo.serial}"

    def clean(self):
        # Validación 1: Origen y destino no pueden ser iguales
        if self.posicion_origen and self.posicion_destino and self.posicion_origen == self.posicion_destino:
            raise ValidationError("La posición de origen y destino no pueden ser la misma")
        
        # Validación 2: Requiere al menos un tipo de origen y destino
        if not self.posicion_origen and not self.ubicacion_origen:
            raise ValidationError("Debe especificar una ubicación de origen (posición o tipo)")
            
        if not self.posicion_destino and not self.ubicacion_destino:
            raise ValidationError("Debe especificar una ubicación de destino (posición o tipo)")

    def save(self, *args, **kwargs):
        # Autocompletar sede si no está especificada
        if not self.sede:
            if self.dispositivo and self.dispositivo.sede:
                self.sede = self.dispositivo.sede
            elif self.posicion_destino and self.posicion_destino.sede:
                self.sede = self.posicion_destino.sede
        
        # Autogenerar observación si está vacía
        if not self.observacion:
            self.observacion = self.generar_observacion()
        
        super().save(*args, **kwargs)

    def generar_observacion(self):
        partes = [f"Dispositivo: {self.dispositivo.serial}"]
        
        if self.posicion_origen:
            partes.append(f"Desde posición: {self.posicion_origen.nombre}")
        elif self.ubicacion_origen:
            partes.append(f"Desde: {self.get_ubicacion_origen_display()}")
        
        if self.posicion_destino:
            partes.append(f"Hacia posición: {self.posicion_destino.nombre}")
        elif self.ubicacion_destino:
            partes.append(f"Hacia: {self.get_ubicacion_destino_display()}")
        
        if self.encargado:
            partes.append(f"Realizado por: {self.encargado.nombre_completo}")
        
        return " | ".join(partes)

# Señales
@receiver(pre_save, sender='dispositivos.Dispositivo')
def capturar_posicion_anterior(sender, instance, **kwargs):
    if instance.pk:
        try:
            original = sender.objects.get(pk=instance.pk)
            instance._posicion_anterior = original.posicion
        except sender.DoesNotExist:
            instance._posicion_anterior = None

@receiver(post_save, sender='dispositivos.Dispositivo')
def registrar_movimiento_automatico(sender, instance, created, **kwargs):
    if created or not hasattr(instance, '_posicion_anterior'):
        return
    
    if instance._posicion_anterior != instance.posicion:
        try:
            request = kwargs.get('request')
            user = getattr(request, 'user', None) if request else None
            encargado = user.roluser if (user and hasattr(user, 'roluser')) else None
            
            with transaction.atomic():
                Movimiento.objects.create(
                    dispositivo=instance,
                    posicion_origen=instance._posicion_anterior,
                    posicion_destino=instance.posicion,
                    encargado=encargado,
                    observacion="Movimiento automático por cambio de posición",
                    sede=instance.sede
                )
        except Exception as e:
            logger.error(f"Error al registrar movimiento automático: {str(e)}")

@receiver(pre_save, sender=Dispositivo)
def guardar_estado_anterior(sender, instance, **kwargs):
    if instance.pk:
        try:
            instance._estado_anterior = Dispositivo.objects.get(pk=instance.pk)
        except Dispositivo.DoesNotExist:
            instance._estado_anterior = None

@receiver(post_save, sender=Dispositivo)
def registrar_cambios_historial(sender, instance, created, **kwargs):
    from django.contrib.auth import get_user # type: ignore
    from django.core.exceptions import ObjectDoesNotExist # type: ignore
    
    try:
        request = kwargs.get('request', None)
        if request:
            usuario_actual = request.user
        else:
            usuario_actual = None
    except ObjectDoesNotExist:
        usuario_actual = None

    cambios = {}
    estado_anterior = getattr(instance, '_estado_anterior', None)
    sede = instance.posicion.sede.nombre if instance.posicion and instance.posicion.sede else None

    if created:
        for field in instance._meta.fields:
            nombre = field.name
            valor = getattr(instance, nombre)
            cambios[nombre] = {"antes": None, "despues": str(valor)}

        Historial.objects.create(
            dispositivo=instance,
            usuario=usuario_actual,
            cambios=cambios,
            tipo_cambio=Historial.TipoCambio.CREACION,
            modelo_afectado="Dispositivo",
            instancia_id=instance.id,
            sede_nombre=sede,
            fecha_modificacion=timezone.now()  
        )
        return

    if estado_anterior:
        for field in instance._meta.fields:
            nombre = field.name
            valor_anterior = getattr(estado_anterior, nombre)
            valor_nuevo = getattr(instance, nombre)

            if valor_anterior != valor_nuevo:
                cambios[nombre] = {"antes": str(valor_anterior), "despues": str(valor_nuevo)}

    if cambios:
        Historial.objects.create(
            dispositivo=instance,
            usuario=usuario_actual,
            cambios=cambios,
            tipo_cambio=Historial.TipoCambio.MODIFICACION,
            modelo_afectado="Dispositivo",
            instancia_id=instance.id,
            sede_nombre=sede
        )



@receiver(user_logged_in)
def registrar_login(sender, request, user, **kwargs):
    sede = getattr(user, 'sede', None)
    hace_un_minuto = now() - timedelta(minutes=1)

    if Historial.objects.filter(
        usuario=user,
        tipo_cambio=Historial.TipoCambio.LOGIN,
        fecha_modificacion__gte=hace_un_minuto
    ).exists():
        return

    Historial.objects.create(
        usuario=user,
        cambios={"mensaje": "Inicio de sesión exitoso"},
        tipo_cambio=Historial.TipoCambio.LOGIN,
        modelo_afectado="Usuario",
        instancia_id=user.id,
        sede_nombre=str(sede) if sede else None
    )

@receiver(post_delete)
def registrar_eliminacion(sender, instance, **kwargs):
    if sender.__name__ in ['Dispositivo', 'Movimiento', 'RolUser', 'Usuario']:
        sede = None
        usuario = getattr(instance, 'usuario', None)

        if hasattr(instance, 'posicion') and instance.posicion and instance.posicion.sede:
            sede = instance.posicion.sede.nombre

        Historial.objects.create(
            cambios={"mensaje": f"Instancia de {sender.__name__} eliminada", "valores": str(instance)},
            tipo_cambio=Historial.TipoCambio.ELIMINACION,
            modelo_afectado=sender.__name__,
            instancia_id=instance.id,
            usuario=usuario,
            sede_nombre=sede
        )
        
@receiver(post_save, sender=Movimiento)
def actualizar_posicion_despues_movimiento(sender, instance, created, **kwargs):
    """
    Actualiza automáticamente la posición del dispositivo cuando se confirma un movimiento
    """
    if instance.confirmado and instance.posicion_destino and instance.dispositivo:
        dispositivo = instance.dispositivo
        posicion_anterior = dispositivo.posicion
        
        # Remover de posición anterior si existe
        if posicion_anterior:
            posicion_anterior.dispositivos.remove(dispositivo)
        
        # Agregar a nueva posición
        instance.posicion_destino.dispositivos.add(dispositivo)
        
        # Actualizar dispositivo
        dispositivo.posicion = instance.posicion_destino
        dispositivo.sede = instance.posicion_destino.sede if instance.posicion_destino.sede else instance.sede
        dispositivo.save()
        
        # Registrar en el historial
        Historial.objects.create(
            dispositivo=dispositivo,
            usuario=instance.encargado,
            tipo_cambio=Historial.TipoCambio.MOVIMIENTO,
            cambios={
                "movimiento_id": instance.id,
                "posicion_anterior": posicion_anterior.id if posicion_anterior else None,
                "posicion_nueva": instance.posicion_destino.id
            }
        )
        
        


from django.db import models
from django.core.validators import MinLengthValidator

class UsuarioExterno(models.Model):
    """Modelo para usuarios externos que no están en el sistema de autenticación"""
    TIPOS_DOCUMENTO = [
        ('CC', 'Cédula de Ciudadanía'),
        ('CE', 'Cédula de Extranjería'),
        ('PASAPORTE', 'Pasaporte'),
    ]
    
    tipo_documento = models.CharField(max_length=10, choices=TIPOS_DOCUMENTO, default='CC')
    documento = models.CharField(
        max_length=20,
        unique=True,
        validators=[MinLengthValidator(5)],
        help_text="Número de documento de identidad"
    )
    nombre_completo = models.CharField(max_length=150)
    cargo = models.CharField(max_length=100, null=True)
    telefono = models.CharField(max_length=15, blank=True, null=True)
    email = models.EmailField(max_length=100, blank=True, null=True)
    fecha_registro = models.DateTimeField(auto_now_add=True, null=True)
    activo = models.BooleanField(default=True)
    
    class Meta:
        verbose_name = 'Usuario Externo'
        verbose_name_plural = 'Usuarios Externos'
        ordering = ['nombre_completo']
    
    def __str__(self):
        return f"{self.nombre_completo} ({self.get_tipo_documento_display()} {self.documento})"

from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

class AsignacionDispositivo(models.Model):
    """Modelo para asignar dispositivos a usuarios externos"""
    ESTADOS = [
        ('VIGENTE', 'Vigente'),
        ('DEVUELTO', 'Devuelto'),
        ('VENCIDO', 'Vencido'),
    ]
    
    UBICACIONES_ASIGNACION = [
        ('CASA', 'Casa'),
        ('CLIENTE', 'Cliente'),
        ('SEDE', 'Sede'),
        ('OFICINA', 'Oficina'),
        ('HIBRIDO', 'Hibrido'),
    ]
    
    usuario = models.ForeignKey(
        UsuarioExterno,
        on_delete=models.CASCADE,
        related_name='asignaciones',
        verbose_name='Usuario asignado'
    )
    dispositivo = models.ForeignKey(
        Dispositivo,
        on_delete=models.CASCADE,
        related_name='asignaciones_externas',
        verbose_name='Dispositivo asignado'
    )
    fecha_asignacion = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Fecha de asignación'
    )
    fecha_devolucion = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Fecha de devolución'
    )
    estado = models.CharField(
        max_length=10,
        choices=ESTADOS,
        default='VIGENTE',
        verbose_name='Estado de asignación'
    )
    ubicacion_asignada = models.CharField(
        max_length=20,
        choices=UBICACIONES_ASIGNACION,
        default='CASA',
        verbose_name='Ubicación de uso',
        help_text="Ubicación donde se usará el dispositivo"
    )
    asignado_por = models.ForeignKey(
        'RolUser',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='asignaciones_realizadas',
        verbose_name='Asignado por'
    )
    observaciones = models.TextField(
        blank=True,
        null=True,
        verbose_name='Observaciones'
    )
    
    class Meta:
        verbose_name = 'Asignación de Dispositivo'
        verbose_name_plural = 'Asignaciones de Dispositivos'
        ordering = ['-fecha_asignacion']
        constraints = [
            models.UniqueConstraint(
                fields=['usuario', 'dispositivo'],
                condition=models.Q(estado='VIGENTE'),
                name='unique_vigente_usuario_dispositivo'
            )
        ]
    
    def __str__(self):
        return f"{self.dispositivo} asignado a {self.usuario} ({self.get_estado_display()})"
    
def clean(self):
    """Validaciones adicionales antes de guardar"""
    # Validar que el dispositivo esté en buen estado y disponible
    if self.estado == 'VIGENTE':
        dispositivo = self.dispositivo
        
        # Verificar estado físico del dispositivo (ahora permite BUENO o STOCK)
        if dispositivo.estado not in ['BUENO', 'BODEGA_CN', 'BODEGA', 'SEDE', 'STOCK']:
            raise ValidationError(
                f"El dispositivo no está en un estado asignable. "
                f"Estado actual: {dispositivo.get_estado_display()}. "
                f"Solo se pueden asignar dispositivos en estado BUENO o STOCK."
            )
        
        # Verificar disponibilidad
        if dispositivo.estado_uso != 'DISPONIBLE':
            raise ValidationError(
                f"El dispositivo no está disponible. "
                f"Estado de uso: {dispositivo.get_estado_uso_display()}"
            )
            # Verificar disponibilidad
            if dispositivo.estado_uso != 'DISPONIBLE':
                raise ValidationError(
                    f"El dispositivo no está disponible. "
                    f"Estado de uso: {dispositivo.get_estado_uso_display()}"
                )
            
            # Validar que no esté asignado a otro usuario
            asignaciones_vigentes = AsignacionDispositivo.objects.filter(
                dispositivo=dispositivo,
                estado='VIGENTE'
            ).exclude(pk=self.pk if self.pk else None)
            
            if asignaciones_vigentes.exists():
                raise ValidationError("Este dispositivo ya está asignado a otro usuario")
        
        # Validar ubicación
        if self.ubicacion_asignada not in dict(self.UBICACIONES_ASIGNACION).keys():
            raise ValidationError("Ubicación de asignación no válida")
    
    def save(self, *args, **kwargs):
        """Sobreescribir save para manejar estados"""
        self.full_clean()  # Ejecuta las validaciones de clean()
        
        # Si es nueva asignación, actualizar estado del dispositivo
        if self.pk is None and self.estado == 'VIGENTE':
            self.dispositivo.estado_uso = 'EN_USO'
            self.dispositivo.save()
        
        super().save(*args, **kwargs)
    
    def marcar_devuelto(self):
        """Método para manejar devoluciones"""
        if self.estado != 'VIGENTE':
            raise ValidationError("Solo se pueden devolver asignaciones vigentes")
        
        self.estado = 'DEVUELTO'
        self.fecha_devolucion = timezone.now()
        self.dispositivo.estado_uso = 'DISPONIBLE'
        self.dispositivo.save()
        self.save()

class RegistroMovimientoDispositivo(models.Model):
    """Modelo para registrar entradas y salidas de dispositivos asignados"""
    TIPO_MOVIMIENTO = [
        ('ENTRADA', 'Entrada'),
        ('SALIDA', 'Salida'),
    ]
    
    asignacion = models.ForeignKey(
        AsignacionDispositivo,
        on_delete=models.CASCADE,
        related_name='movimientos'
    )
    tipo = models.CharField(max_length=7, choices=TIPO_MOVIMIENTO)
    fecha = models.DateField(auto_now_add=True)
    hora = models.TimeField(auto_now_add=True)
    observaciones = models.TextField(blank=True, null=True)
    registrado_por = models.ForeignKey(
        'RolUser',
        on_delete=models.SET_NULL,
        null=True,
        related_name='registros_ingreso'
    )
    
    class Meta:
        verbose_name = 'Registro de Movimiento'
        verbose_name_plural = 'Registros de Movimientos'
        ordering = ['-fecha', '-hora']
    
    def __str__(self):
        return f"{self.get_tipo_display()} - {self.asignacion.dispositivo} - {self.fecha} {self.hora}"
    
    def clean(self):
        # Validar que el movimiento sea coherente con el historial
        ultimo_movimiento = RegistroMovimientoDispositivo.objects.filter(
            asignacion=self.asignacion
        ).order_by('-fecha', '-hora').first()
        
        if ultimo_movimiento:
            if ultimo_movimiento.tipo == self.tipo:
                raise ValidationError(
                    f"No puede registrar dos {self.get_tipo_display().lower()}s consecutivas"
                )

@receiver(pre_save, sender=AsignacionDispositivo)
def actualizar_estado_dispositivo(sender, instance, **kwargs):
    """
    Actualiza el estado del dispositivo cuando se asigna o devuelve
    """
    if instance.estado == 'VIGENTE':
        instance.dispositivo.ubicacion = instance.ubicacion_asignada
        instance.dispositivo.estado_uso = 'EN_USO'
        instance.dispositivo.save()
    elif instance.estado in ['DEVUELTO', 'VENCIDO']:
        instance.dispositivo.ubicacion = 'SEDE'
        instance.dispositivo.estado_uso = 'DISPONIBLE'
        instance.dispositivo.save()