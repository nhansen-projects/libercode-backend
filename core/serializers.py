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
    document = serializers.JSONField(required=False, allow_null=True)
    favorite = serializers.SerializerMethodField()
    is_owner = serializers.SerializerMethodField()
    
    class Meta:
        model = Entry
        fields = ['id', 'title', 'body', 'shared', 'author', 'tags', 'tag_ids', 'favorite', 'created_at', 'last_edited', 'is_owner']
        read_only_fields = ['id', 'author', 'favorite', 'created_at', 'last_edited', 'is_owner']

    def get_is_owner(self, obj):
        request = self.context.get('request')
        return obj.is_owned_by(request.user) if request and request.user.is_authenticated else False
    
    def get_favorite(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return Favorite.objects.filter(user=request.user, entry=obj).exists()
        return False

    def _resolve_tags_from_input(self, validated_data):
        # 1) Preferred: tag_ids input (mapped to 'tags')
        tags_from_ids = validated_data.pop('tags', None)
        if tags_from_ids is not None:
            return list(tags_from_ids)

        # 2) Fallback: raw "tags": ["Tes", ...] from frontend (Less efficient.)
        raw_tags = self.initial_data.get('tags', None)
        if raw_tags is None:
            return None

        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]

        if not isinstance(raw_tags, list):
            raise serializers.ValidationError({'tags': 'Must be a list of tag strings.'})

        resolved = []
        seen = set()
        for item in raw_tags:
            if not isinstance(item, str):
                raise serializers.ValidationError({'tags': 'Each tag must be a string.'})

            value = item.strip().lower() # Check for whitespace + to lowercase to avoid duplicates like "Test" vs "test"
            if not value:
                continue

            if value in seen: # Avoid duplicate tags
                continue
            seen.add(value)

            tag, _ = Tag.objects.get_or_create(value=value)
            resolved.append(tag)

        return resolved

    def create(self, validated_data):
        tags = self._resolve_tags_from_input(validated_data)
        entry = Entry.objects.create(**validated_data)
        if tags is not None:
            entry.tags.set(tags)
        return entry

    def update(self, instance, validated_data):
        tags = self._resolve_tags_from_input(validated_data)
        instance = super().update(instance, validated_data)
        if tags is not None:
            instance.tags.set(tags)
        return instance


class FavoriteSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    entry = EntrySerializer(read_only=True)
    entry_id = serializers.PrimaryKeyRelatedField(
        queryset=Entry.objects.none(), 
        source='entry',
        write_only=True
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            self.fields['entry_id'].queryset = Entry.objects.filter(author=request.user)
    
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