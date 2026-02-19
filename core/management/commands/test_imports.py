from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Test if API views can be imported successfully'
    
    def handle(self, *args, **options):
        try:
            # Test importing api_views
            from core import api_views
            self.stdout.write(self.style.SUCCESS('✅ API views imported successfully'))
            
            # Test importing REST framework components
            from rest_framework import generics, permissions, status, exceptions
            self.stdout.write(self.style.SUCCESS('✅ REST framework imported successfully'))
            
            # Test REST framework settings
            rest_settings = getattr(settings, 'REST_FRAMEWORK', {})
            self.stdout.write(self.style.SUCCESS(f'✅ REST Framework settings: {rest_settings}'))
            
            # Test specific view imports
            from core.api_views import EntryListCreateView
            self.stdout.write(self.style.SUCCESS('✅ EntryListCreateView imported successfully'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Import failed: {type(e).__name__}: {e}'))
            import traceback
            self.stdout.write(self.style.ERROR(traceback.format_exc()))