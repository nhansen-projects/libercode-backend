from rest_framework import serializers
from .models import Entry, Tag, Favorite
from django.contrib.auth import get_user_model

User = get_user_model()


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'value', 'created_at']
        read_only_fields = ['id', 'created_at']


class EntrySerializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField()
    tags = TagSerializer(many=True, read_only=True)
    tag_ids = serializers.PrimaryKeyRelatedField(
        many=True, 
        queryset=Tag.objects.all(), 
        source='tags',
        required=False,
        write_only=True
    )
    favorite = serializers.SerializerMethodField()
    
    class Meta:
        model = Entry
        fields = ['id', 'title', 'body', 'shared', 'author', 'tags', 'tag_ids', 'favorite', 'created_at', 'last_edited']
        read_only_fields = ['id', 'author', 'favorite', 'created_at', 'last_edited']
    
    def get_favorite(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return Favorite.objects.filter(user=request.user, entry=obj).exists()
        return False
    
    def create(self, validated_data):
        tags = validated_data.pop('tags', [])
        entry = Entry.objects.create(**validated_data)
        entry.tags.set(tags)
        return entry
    
    def update(self, instance, validated_data):
        tags = validated_data.pop('tags', [])
        instance = super().update(instance, validated_data)
        instance.tags.set(tags)
        return instance


class FavoriteSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    entry = EntrySerializer(read_only=True)
    entry_id = serializers.PrimaryKeyRelatedField(
        queryset=Entry.objects.all(), 
        source='entry',
        write_only=True
    )
    
    class Meta:
        model = Favorite
        fields = ['id', 'user', 'entry', 'entry_id', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']
    
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        read_only_fields = ['id']