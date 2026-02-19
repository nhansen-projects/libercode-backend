from django.core.management.base import BaseCommand
from core.models import EncryptionKey
from core.utils import SecurityUtils
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Generate and rotate encryption keys'

    def add_arguments(self, parser):
        parser.add_argument(
            '--key-type',
            type=str,
            choices=['fernet', 'aes', 'both'],
            default='both',
            help='Type of encryption key to generate (fernet, aes, or both)'
        )
        parser.add_argument(
            '--description',
            type=str,
            default='Auto-generated encryption key',
            help='Description for the new key'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force generation even if active key exists'
        )

    def handle(self, *args, **options):
        key_type = options['key_type']
        description = options['description']
        force = options['force']

        self.stdout.write(f"Starting encryption key generation...")
        
        if key_type in ['fernet', 'both']:
            self._generate_fernet_key(description, force)
        
        if key_type in ['aes', 'both']:
            self._generate_aes_key(description, force)
        
        self.stdout.write(self.style.SUCCESS('Encryption key generation completed successfully'))

    def _generate_fernet_key(self, description, force):
        """Generate Fernet encryption key"""
        try:
            # Check if active key exists and force is not set
            try:
                active_key = EncryptionKey.get_active_key('fernet')
                if active_key and not force:
                    self.stdout.write(
                        self.style.WARNING(
                            f'Active Fernet key already exists (created: {active_key.created_at}). '
                            f'Use --force to replace it.'
                        )
                    )
                    return
            except Exception:
                # Table doesn't exist yet, proceed with key generation
                pass
            
            self.stdout.write('Generating new Fernet encryption key...')
            key = EncryptionKey.generate_fernet_key(description)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully generated Fernet key: {key.key[:20]}... (ID: {key.id})'
                )
            )
            
            # Log the event
            logger.info(f'Generated new Fernet encryption key (ID: {key.id})')
            
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f'Failed to generate Fernet key: {str(e)}')
            )
            logger.error(f'Failed to generate Fernet key: {str(e)}', exc_info=True)

    def _generate_aes_key(self, description, force):
        """Generate AES encryption key"""
        try:
            # Check if active key exists and force is not set
            try:
                active_key = EncryptionKey.get_active_key('aes')
                if active_key and not force:
                    self.stdout.write(
                        self.style.WARNING(
                            f'Active AES key already exists (created: {active_key.created_at}). '
                            f'Use --force to replace it.'
                        )
                    )
                    return
            except Exception:
                # Table doesn't exist yet, proceed with key generation
                pass
            
            self.stdout.write('Generating new AES encryption key...')
            key = EncryptionKey.generate_aes_key(description)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully generated AES key: {key.key[:20]}... (ID: {key.id})'
                )
            )
            
            # Log the event
            logger.info(f'Generated new AES encryption key (ID: {key.id})')
            
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f'Failed to generate AES key: {str(e)}')
            )
            logger.error(f'Failed to generate AES key: {str(e)}', exc_info=True)