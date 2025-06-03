from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
import logging
from django.contrib.auth.password_validation import validate_password
logger = logging.getLogger(__name__)
User = get_user_model()

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'is_active', 'created_at', 'created_by']
        read_only_fields = ['created_at', 'created_by']  

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = [
            'phone_number', 'address', 'city', 'state', 
            'country', 'postal_code', 'bio', 'profile_picture', 
            'date_of_birth', 'gender'
        ]
        extra_kwargs = {
            'profile_picture': {'required': False, 'allow_null': True}
        }

class UserSerializer(serializers.ModelSerializer):
    roles = RoleSerializer(many=True, read_only=True)
    profile = UserProfileSerializer(required=False)
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'is_active', 'is_staff', 'is_verified',
            'roles', 'last_login', 'profile'
        ]
        read_only_fields = [
            'id', 'is_active', 'is_staff', 
            'is_verified', 'last_login', 'username'
        ]
        extra_kwargs = {
            'username': {'required': False}  # Will be auto-populated from email
        }

    def create(self, validated_data):
        # Ensure username is set to email if not provided
        if 'username' not in validated_data or not validated_data['username']:
            validated_data['username'] = validated_data['email']
        return super().create(validated_data)

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', None)
        
        # Prevent username updates through the API
        if 'username' in validated_data:
            del validated_data['username']
            
        instance = super().update(instance, validated_data)
        
        if profile_data:
            profile_serializer = UserProfileSerializer(
                instance.profile, 
                data=profile_data, 
                partial=True
            )
            if profile_serializer.is_valid(raise_exception=True):
                profile_serializer.save()
        
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        
        # Ensure username is always included in output (backward compatibility)
        if 'username' not in representation or not representation['username']:
            representation['username'] = instance.email
            
        # Add role names as a flat list for convenience
        representation['role_names'] = [role.name for role in instance.roles.all()]
        
        # Add role IDs as a flat list
        representation['role_ids'] = [role.id for role in instance.roles.all()]
        
        return representation

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})
    profile = UserProfileSerializer(required=False)
    
    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name', 'profile']
        extra_kwargs = {'password': {'write_only': True}}
    
    def create(self, validated_data):
        profile_data = validated_data.pop('profile', None)
        user = User.objects.create_user(**validated_data)
        
        if profile_data:
            UserProfile.objects.create(user=user, **profile_data)
        
        default_role = Role.objects.get(name='visitor')
        user.roles.add(default_role)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})
    otp = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        email = attrs.get('email').lower().strip()
        password = attrs.get('password')
        otp = attrs.get('otp')
        
        if not email or not password:
            raise serializers.ValidationError({
                'detail': 'Both email and password are required',
                'code': 'missing_credentials'
            })
        
        try:
            user = User.objects.get(email=email)
            
            if not user.check_password(password):
                user.record_failed_login()
                raise serializers.ValidationError({
                    'detail': 'Invalid email or password',
                    'code': 'invalid_credentials'
                })
            
            if user.is_account_locked():
                raise serializers.ValidationError({
                    'detail': 'Account temporarily locked. Please try again later.',
                    'code': 'account_locked'
                })
            
            # If OTP is provided, verify it
            if otp:
                if not user.otp or user.otp != otp:
                    raise serializers.ValidationError({
                        'detail': 'Invalid OTP',
                        'code': 'invalid_otp'
                    })
                if timezone.now() > user.otp_created_at + timedelta(minutes=10):
                    raise serializers.ValidationError({
                        'detail': 'OTP expired',
                        'code': 'otp_expired'
                    })
                user.otp = None
                user.otp_created_at = None
                user.record_login()
            
            attrs['user'] = user
            return attrs
            
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'detail': 'Invalid email or password',
                'code': 'invalid_credentials'
            })

class AuthTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuthToken
        fields = ['key', 'expires_at']

class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['profile_picture']

class AdSerializer(serializers.ModelSerializer):
    is_currently_active = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = Ad
        fields = [
            'id', 'title', 'description', 'image', 'content', 
            'target_url', 'is_active', 'start_date', 'end_date',
            'views', 'clicks', 'created_at', 'is_currently_active'
        ]
        read_only_fields = ['views', 'clicks', 'created_at']

class EventRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventRegistration
        fields = ['id', 'full_name', 'email', 'phone', 'organization', 'registered_at']
        read_only_fields = ['registered_at']

class EventSerializer(serializers.ModelSerializer):
    registrations = EventRegistrationSerializer(many=True, read_only=True)
    status = serializers.SerializerMethodField()
    
    def get_status(self, obj):
        if obj.is_upcoming():
            return "Upcoming"
        elif obj.is_ongoing():
            return "Ongoing"
        return "Completed"

    class Meta:
        model = Event
        fields = [
            'id', 'title', 'description', 'event_type', 
            'location', 'online_link', 'start_date', 'end_date',
            'image', 'banner', 'is_public', 'is_active',
            'registrations', 'status', 'created_at'
        ]
        read_only_fields = ['created_at', 'status']        
class BlogCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = BlogCategory
        fields = ['id', 'name', 'slug', 'icon']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name']

class BlogCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = BlogComment
        fields = ['id', 'user', 'content', 'created_at', 'is_approved']
        read_only_fields = ['user', 'created_at']

class BlogPostSerializer(serializers.ModelSerializer):
    author = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), write_only=True, required=False, allow_null=True)
    category = serializers.PrimaryKeyRelatedField(queryset=BlogCategory.objects.all(), write_only=True, required=False, allow_null=True)
    category_details = BlogCategorySerializer(source="category", read_only=True)
    author_details = UserSerializer(source="author", read_only=True)
    comments = BlogCommentSerializer(many=True, read_only=True)
    like_count = serializers.IntegerField(read_only=True)
    is_liked = serializers.SerializerMethodField()

    def get_is_liked(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.likes.filter(user=request.user).exists()
        return False

    class Meta:
        model = BlogPost
        fields = [
            'id', 'title', 'slug', 'author', 'author_details','category_details','category',
            'content', 'excerpt', 'featured_image', 'status',
            'is_featured', 'published_date', 'comments',
            'like_count', 'is_liked', 'created_at'
        ]
        read_only_fields = ['slug', 'author_details','category_details','published_date', 'created_at', 'like_count']
  
class AnnouncementSerializer(serializers.ModelSerializer):
    is_visible = serializers.SerializerMethodField()
    
    def get_is_visible(self, obj):
        return obj.is_visible()
    
    class Meta:
        model = Announcement
        fields = [
            'id', 
            'title', 
            'message', 
            'is_active', 
            'show_until', 
            'created_at',
            'is_visible'
        ]
        read_only_fields = ['created_at', 'is_visible'] 

class GalleryCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = GalleryCategory
        fields = ['id', 'name', 'slug', 'icon']

class GalleryItemCreateSerializer(serializers.ModelSerializer):
    categories = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=GalleryCategory.objects.all(),
        required=False
    )
    
    class Meta:
        model = GalleryItem
        fields = [
            'id', 'title', 'description', 'categories',
            'media_type', 'image', 'video_url', 'thumbnail',
            'is_active'
        ]

class GalleryItemSerializer(serializers.ModelSerializer):
    categories = GalleryCategorySerializer(many=True, read_only=True)
    media_url = serializers.SerializerMethodField()
    thumbnail_url = serializers.SerializerMethodField()
    uploaded_by = serializers.StringRelatedField()
    
    def get_media_url(self, obj):
        request = self.context.get('request')
        if obj.media_type == 'image' and obj.image:
            return request.build_absolute_uri(obj.image.url)
        return obj.video_url

    def get_thumbnail_url(self, obj):
        request = self.context.get('request')
        if obj.thumbnail:
            return request.build_absolute_uri(obj.thumbnail.url)
        return self.get_media_url(obj)

    def get_image_url(self, obj):
        request = self.context.get('request')
        if obj.image:
            return request.build_absolute_uri(obj.image.url)
        return None

    class Meta:
        model = GalleryItem
        fields = '__all__'  
                    