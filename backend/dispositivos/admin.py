from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django import forms
from .models import (
    Sede, 
    Servicios, 
    Posicion, 
    Dispositivo, 
    Movimiento, 
    Historial, 
    RolUser,
    UsuarioExterno,
    AsignacionDispositivo,
    RegistroMovimientoDispositivo,
    Piso,
    SubPiso
)

# Admin para RolUser
@admin.register(RolUser)
class RolUserAdmin(UserAdmin):
    list_display = ('username', 'rol', 'nombre', 'email', 'celular', 'documento', 'is_active', 'is_staff')
    search_fields = ('username', 'nombre', 'email', 'documento')
    list_filter = ('rol', 'is_active', 'is_staff', 'sedes')
    filter_horizontal = ('groups', 'user_permissions', 'sedes')

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Información personal', {'fields': ('nombre', 'email', 'celular', 'documento')}),
        ('Rol y permisos', {'fields': ('rol', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions', 'sedes')}),
        ('Fechas importantes', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'email', 'nombre', 'celular', 'documento', 'rol', 'is_active', 'is_staff', 'sedes'),
        }),
    )

# Admin para Sede
@admin.register(Sede)
class SedeAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'ciudad', 'direccion')
    search_fields = ('nombre', 'ciudad')
    list_filter = ('ciudad',)

# Admin para Piso
@admin.register(Piso)
class PisoAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'sede', 'orden', 'es_principal')
    search_fields = ('nombre', 'sede__nombre')
    list_filter = ('sede', 'es_principal')
    ordering = ('sede', 'orden')

# Admin para SubPiso
@admin.register(SubPiso)
class SubPisoAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'piso_padre', 'sede', 'orden')
    search_fields = ('nombre', 'piso_padre__nombre', 'sede__nombre')
    list_filter = ('piso_padre', 'sede')
    ordering = ('piso_padre', 'orden')

# Admin para Servicios
@admin.register(Servicios)
class ServiciosAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'codigo_analitico', 'get_sedes', 'color')
    list_filter = ('sedes',)
    filter_horizontal = ('sedes',)

    def get_sedes(self, obj):
        return ", ".join([sede.nombre for sede in obj.sedes.all()])
    get_sedes.short_description = "Sedes"

# Admin para Dispositivo
@admin.register(Dispositivo)
class DispositivoAdmin(admin.ModelAdmin):
    list_display = ('tipo', 'marca', 'modelo', 'serial', 'razon_social', 'sede', 'estado', 'ubicacion', 'estado_uso')
    search_fields = ('serial', 'modelo', 'marca', 'razon_social', 'placa_cu')
    list_filter = ('tipo', 'estado', 'sede', 'razon_social', 'ubicacion', 'estado_uso')
    list_editable = ('estado', 'estado_uso')
    ordering = ('modelo',)
    raw_id_fields = ('posicion', 'subpiso', 'piso')
    
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        form.save_m2m()

# Admin para Posicion
@admin.register(Posicion)
class PosicionAdmin(admin.ModelAdmin):
    list_display = ('nombre', 'piso', 'servicio', 'estado', 'fila', 'columna')
    search_fields = ('nombre', 'piso__nombre', 'servicio__nombre')
    list_filter = ('piso', 'servicio', 'estado')
    filter_horizontal = ('dispositivos',)
    
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        form.save_m2m()

# Admin para Movimiento
@admin.register(Movimiento)
class MovimientoAdmin(admin.ModelAdmin):
    list_display = ('dispositivo', 'encargado', 'fecha_movimiento', 'posicion_origen', 'posicion_destino', 'sede', 'confirmado')
    list_filter = ('fecha_movimiento', 'posicion_origen', 'posicion_destino', 'sede', 'confirmado')
    search_fields = ('dispositivo__serial', 'dispositivo__modelo', 'encargado__username')
    date_hierarchy = 'fecha_movimiento'
    ordering = ('-fecha_movimiento',)
    raw_id_fields = ('dispositivo', 'posicion_origen', 'posicion_destino')

# Admin para Historial
@admin.register(Historial)
class HistorialAdmin(admin.ModelAdmin):
    list_display = ('dispositivo', 'usuario', 'fecha_modificacion', 'tipo_cambio', 'modelo_afectado')
    search_fields = ('dispositivo__serial', 'usuario__username', 'tipo_cambio', 'modelo_afectado')
    list_filter = ('tipo_cambio', 'modelo_afectado')
    date_hierarchy = 'fecha_modificacion'
    raw_id_fields = ('dispositivo', 'usuario')

# Admin para UsuarioExterno
class UsuarioExternoAdminForm(forms.ModelForm):
    class Meta:
        model = UsuarioExterno
        fields = '__all__'

@admin.register(UsuarioExterno)
class UsuarioExternoAdmin(admin.ModelAdmin):
    form = UsuarioExternoAdminForm
    list_display = ('nombre_completo', 'tipo_documento', 'documento', 'cargo', 'activo')
    search_fields = ('nombre_completo', 'documento', 'cargo')
    list_filter = ('tipo_documento', 'activo', 'fecha_registro')
    ordering = ('nombre_completo',)
    readonly_fields = ('fecha_registro',)
    fieldsets = (
        ('Información Personal', {
            'fields': ('tipo_documento', 'documento', 'nombre_completo')
        }),
        ('Información Laboral', {
            'fields': ('cargo',)
        }),
        ('Contacto', {
            'fields': ('telefono', 'email')
        }),
        ('Estado y Observaciones', {
            'fields': ('activo', 'fecha_registro')
        }),
    )

# Inline para AsignacionDispositivo
class AsignacionDispositivoInline(admin.TabularInline):
    model = AsignacionDispositivo
    extra = 0
    fields = ('dispositivo', 'fecha_asignacion', 'estado', 'ubicacion_asignada')
    readonly_fields = ('fecha_asignacion',)
    show_change_link = True

# Filtro para Dispositivo en Asignaciones
class DispositivoFilter(admin.SimpleListFilter):
    title = 'Dispositivo'
    parameter_name = 'dispositivo'

    def lookups(self, request, model_admin):
        dispositivos = Dispositivo.objects.filter(asignaciones_externas__isnull=False).distinct()
        return [(d.id, f"{d.tipo} - {d.serial}") for d in dispositivos]

    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(dispositivo__id=self.value())

# Admin para AsignacionDispositivo
@admin.register(AsignacionDispositivo)
class AsignacionDispositivoAdmin(admin.ModelAdmin):
    list_display = ('usuario_info', 'dispositivo_info', 'fecha_asignacion', 'estado', 'ubicacion_asignada', 'asignado_por')
    search_fields = (
        'usuario__nombre_completo', 
        'usuario__documento',
        'dispositivo__serial',
        'dispositivo__modelo'
    )
    list_filter = ('estado', 'ubicacion_asignada', DispositivoFilter, 'fecha_asignacion')
    date_hierarchy = 'fecha_asignacion'
    raw_id_fields = ('usuario', 'dispositivo')
    readonly_fields = ('fecha_asignacion', 'asignado_por')
    
    fieldsets = (
        (None, {
            'fields': ('usuario', 'dispositivo', 'asignado_por')
        }),
        ('Estado y Ubicación', {
            'fields': ('estado', 'ubicacion_asignada', 'fecha_devolucion')
        }),
        ('Observaciones', {
            'fields': ('observaciones',)
        }),
    )

    def usuario_info(self, obj):
        return f"{obj.usuario.nombre_completo} ({obj.usuario.documento})"
    usuario_info.short_description = 'Usuario'
    
    def dispositivo_info(self, obj):
        return f"{obj.dispositivo.tipo} {obj.dispositivo.marca} - {obj.dispositivo.serial}"
    dispositivo_info.short_description = 'Dispositivo'

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.asignado_por = request.user
        super().save_model(request, obj, form, change)

# Admin para RegistroMovimientoDispositivo
@admin.register(RegistroMovimientoDispositivo)
class RegistroMovimientoDispositivoAdmin(admin.ModelAdmin):
    list_display = ('asignacion_info', 'tipo', 'fecha_hora', 'registrado_por')
    search_fields = (
        'asignacion__usuario__nombre_completo',
        'asignacion__usuario__documento',
        'asignacion__dispositivo__serial'
    )
    list_filter = ('tipo', 'fecha')
    date_hierarchy = 'fecha'
    raw_id_fields = ('asignacion', 'registrado_por')
    
    def asignacion_info(self, obj):
        return f"{obj.asignacion.usuario} - {obj.asignacion.dispositivo}"
    asignacion_info.short_description = 'Asignación'
    
    def fecha_hora(self, obj):
        return f"{obj.fecha} {obj.hora}"
    fecha_hora.short_description = 'Fecha y Hora'

    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.registrado_por = request.user
        super().save_model(request, obj, form, change)