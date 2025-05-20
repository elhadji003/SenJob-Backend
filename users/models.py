from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
from .managers import CustomUserManager

class User(AbstractUser):
    username = None

    full_name = models.CharField(max_length=100, verbose_name="Nom complet", null=True, blank=True)

    GENDER_CHOICES = [
        ('man', 'Homme'),
        ('woman', 'Femme'),
    ]
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, default='man')

    email = models.EmailField(unique=True, verbose_name="Email")
    
    phone_validator = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Le numéro de téléphone n'est pas valide.")
    phone = models.CharField(max_length=20, blank=True, validators=[phone_validator], verbose_name="Téléphone")
    
    pays = models.CharField(max_length=100, blank=True, verbose_name="Pays")
    bio = models.TextField(blank=True, verbose_name="Biographie")
    birthday = models.DateField(null=True, blank=True, verbose_name="Date de naissance")
    avatar = models.ImageField(upload_to='avatars/', default='avatars/default.png')
    
    updated_at = models.DateTimeField(auto_now=True)

    ROLE_CHOICES = [
        ('user', 'Utilisateur'),
        ('admin', 'Administrateur'),
        ('community', 'Communauté'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    is_online = models.BooleanField(default=False, verbose_name="En ligne")

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.full_name or f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        return self.full_name or self.first_name or self.email
