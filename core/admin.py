from django.contrib import admin

from django.contrib import admin
from .models import CustomUser, ServiceProvider, ServiceRequest, Review

admin.site.register(CustomUser)
admin.site.register(ServiceProvider)
admin.site.register(ServiceRequest)
admin.site.register(Review)