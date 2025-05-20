from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    

    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'gender', 'password', 'password2', 'phone', 'pays', 'bio', 'birthday', 'avatar', 'role', 'is_online', 'updated_at']
        extra_kwargs = {
            'role': {'default': 'user'},
            'avatar': {'required': False},
            'is_online': {'default': False},
        }

    def validate(self, attrs):
        """ Vérifie que les mots de passe correspondent """
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Les mots de passe ne correspondent pas."})

        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')

        if User.objects.filter(email=validated_data['email']).exists():
            raise serializers.ValidationError({"email": "Cet email est déjà utilisé."})
    
   

        user = User(
            full_name=validated_data['full_name'],
            email=validated_data['email'],
            gender=validated_data.get('gender', 'man'),
            phone=validated_data.get('phone', ''),
            pays=validated_data.get('pays', ''),
            bio=validated_data.get('bio', ''),
            birthday=validated_data.get('birthday'),
            avatar=validated_data.get('avatar', 'avatars/default.png'),
            role=validated_data.get('role', 'user'),
            is_online=validated_data.get('is_online', False)

        )
        user.set_password(validated_data['password'])  # Hacher le mot de passe
        user.save()

        return user

class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'gender', 'phone', 'pays', 'bio', 'birthday', 'avatar']
        extra_kwargs = {
            'avatar': {'required': False},
        }


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'full_name', 'email', 'gender', 'phone', 'pays', 'bio', 'birthday', 'avatar', 'role', 'is_online', 'updated_at']