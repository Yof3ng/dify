"""
Security Tests for Dify - Validates recent security fixes

These tests validate the security fixes identified in the security analysis:
1. API Token Authentication doesn't bypass user authentication
2. Password reset properly persists changes
3. Account profile updates are properly saved
"""

import base64
import secrets
from unittest.mock import MagicMock, patch
import pytest
from flask import Flask
from werkzeug.exceptions import Forbidden, Unauthorized

# Test for Fix #1: API Token Authentication Bypass (Commit 4ee49f3)
class TestApiTokenSecurityFix:
    """Tests for the API token authentication bypass fix"""
    
    def test_api_token_validation_no_auto_login(self):
        """
        Test that API token validation doesn't automatically log in tenant owners.
        This validates the fix for commit 4ee49f3.
        """
        from api.controllers.service_api.wraps import validate_app_token
        from models.model import ApiToken
        from models.account import Tenant, TenantStatus
        from models.model import App
        
        # Mock dependencies
        with patch('api.controllers.service_api.wraps.validate_and_get_api_token') as mock_validate_token, \
             patch('api.controllers.service_api.wraps.db') as mock_db, \
             patch('flask.current_app') as mock_app:
            
            # Setup test data
            mock_api_token = MagicMock(spec=ApiToken)
            mock_api_token.app_id = "app-123"
            mock_api_token.tenant_id = "tenant-123"
            mock_validate_token.return_value = mock_api_token
            
            mock_app_model = MagicMock(spec=App)
            mock_app_model.id = "app-123"
            mock_app_model.status = "normal"
            mock_app_model.enable_api = True
            mock_app_model.tenant_id = "tenant-123"
            
            mock_tenant = MagicMock(spec=Tenant)
            mock_tenant.id = "tenant-123"
            mock_tenant.status = TenantStatus.NORMAL
            
            # Setup database query mocks
            mock_app_query = MagicMock()
            mock_app_query.where.return_value.first.return_value = mock_app_model
            
            mock_tenant_query = MagicMock()
            mock_tenant_query.where.return_value.first.return_value = mock_tenant
            
            mock_db.session.query.side_effect = [mock_app_query, mock_tenant_query]
            
            # Create test decorator
            @validate_app_token
            def test_view(*args, **kwargs):
                return {"status": "success", "args": args, "kwargs": kwargs}
            
            # Test that no automatic login occurs
            result = test_view()
            
            # Verify no login manager calls were made (the dangerous code was removed)
            assert not hasattr(mock_app.login_manager, '_update_request_context_with_user')
            assert result["status"] == "success"
            assert "app_model" in result["kwargs"]
            
    def test_api_token_validation_handles_archived_tenant(self):
        """Test that archived tenants are properly rejected"""
        from api.controllers.service_api.wraps import validate_app_token
        from models.model import ApiToken
        from models.account import Tenant, TenantStatus
        from models.model import App
        
        with patch('api.controllers.service_api.wraps.validate_and_get_api_token') as mock_validate_token, \
             patch('api.controllers.service_api.wraps.db') as mock_db:
            
            # Setup test data with archived tenant
            mock_api_token = MagicMock(spec=ApiToken)
            mock_api_token.app_id = "app-123"
            mock_api_token.tenant_id = "tenant-123"
            mock_validate_token.return_value = mock_api_token
            
            mock_app_model = MagicMock(spec=App)
            mock_app_model.status = "normal"
            mock_app_model.enable_api = True
            mock_app_model.tenant_id = "tenant-123"
            
            mock_tenant = MagicMock(spec=Tenant)
            mock_tenant.status = TenantStatus.ARCHIVE  # Archived tenant
            
            mock_app_query = MagicMock()
            mock_app_query.where.return_value.first.return_value = mock_app_model
            
            mock_tenant_query = MagicMock()
            mock_tenant_query.where.return_value.first.return_value = mock_tenant
            
            mock_db.session.query.side_effect = [mock_app_query, mock_tenant_query]
            
            @validate_app_token
            def test_view(*args, **kwargs):
                return {"status": "success"}
            
            # Should raise Forbidden for archived tenant
            with pytest.raises(Forbidden, match="workspace's status is archived"):
                test_view()


# Test for Fix #2: Password Reset Persistence (Commit de768af)
class TestPasswordResetSecurityFix:
    """Tests for the password reset persistence fix"""
    
    def test_password_reset_persistence(self):
        """
        Test that password reset properly persists changes to database.
        This validates the fix for commit de768af.
        """
        from api.services.account_service import AccountService
        from models.account import Account
        
        with patch('api.services.account_service.db') as mock_db, \
             patch('api.services.account_service.hash_password') as mock_hash, \
             patch('api.services.account_service.compare_password') as mock_compare:
            
            # Setup test account
            mock_account = MagicMock(spec=Account)
            mock_account.password = "old_hashed_password"
            mock_account.password_salt = "old_salt"
            
            # Setup password validation
            mock_compare.return_value = True  # Current password is correct
            mock_hash.return_value = b"new_hashed_password"
            
            # Mock session
            mock_session = MagicMock()
            mock_db.session = mock_session
            
            # Call the method
            result = AccountService.update_account_password(
                mock_account, 
                "current_password", 
                "new_password"
            )
            
            # Verify that db.session.add() was called (the fix)
            mock_session.add.assert_called_once_with(mock_account)
            mock_session.commit.assert_called_once()
            
            # Verify password was updated
            assert mock_account.password is not None
            assert mock_account.password_salt is not None
            assert result == mock_account
            
    def test_password_reset_with_wrong_current_password(self):
        """Test that password reset fails with wrong current password"""
        from api.services.account_service import AccountService
        from services.errors.account import CurrentPasswordIncorrectError
        from models.account import Account
        
        with patch('api.services.account_service.compare_password') as mock_compare:
            mock_account = MagicMock(spec=Account)
            mock_account.password = "hashed_password"
            mock_compare.return_value = False  # Wrong password
            
            with pytest.raises(CurrentPasswordIncorrectError):
                AccountService.update_account_password(
                    mock_account,
                    "wrong_password", 
                    "new_password"
                )


# Test for Fix #3: Account Profile Update (Commit d36ce78)
class TestAccountProfileUpdateFix:
    """Tests for the account profile update persistence fix"""
    
    def test_account_profile_update_with_merge(self):
        """
        Test that account profile updates properly handle detached objects.
        This validates the fix for commit d36ce78.
        """
        from api.services.account_service import AccountService
        from models.account import Account
        
        with patch('api.services.account_service.db') as mock_db:
            # Setup test account (potentially detached)
            mock_account = MagicMock(spec=Account)
            mock_account.name = "Old Name"
            mock_account.interface_theme = "light"
            
            # Setup merged account
            merged_account = MagicMock(spec=Account)
            merged_account.name = "Old Name"
            merged_account.interface_theme = "light"
            
            mock_db.session.merge.return_value = merged_account
            
            # Call the method with updates
            AccountService.update_account(
                mock_account, 
                name="New Name",
                interface_theme="dark"
            )
            
            # Verify that db.session.merge() was called (the fix)
            mock_db.session.merge.assert_called_once_with(mock_account)
            
            # Verify attributes were updated on the merged object
            assert merged_account.name == "New Name"
            assert merged_account.interface_theme == "dark"
    
    def test_account_profile_update_ignores_invalid_fields(self):
        """Test that invalid fields are ignored during update"""
        from api.services.account_service import AccountService
        from models.account import Account
        
        with patch('api.services.account_service.db') as mock_db:
            mock_account = MagicMock(spec=Account)
            # Only has 'name' attribute, not 'invalid_field'
            mock_account.name = "Test"
            del mock_account.invalid_field  # Ensure it doesn't exist
            
            merged_account = MagicMock(spec=Account)
            merged_account.name = "Test"
            mock_db.session.merge.return_value = merged_account
            
            # This should not raise an exception
            AccountService.update_account(
                mock_account,
                name="Updated Name",
                invalid_field="should_be_ignored"
            )
            
            assert merged_account.name == "Updated Name"


# Integration Security Tests
class TestSecurityIntegration:
    """Integration tests for overall security posture"""
    
    def test_no_automatic_privilege_escalation(self):
        """Ensure API requests don't automatically get admin privileges"""
        # This test would require a real Flask app context
        # For now, we verify the dangerous code was removed
        from api.controllers.service_api.wraps import validate_app_token
        import inspect
        
        # Get the source code of the function
        source = inspect.getsource(validate_app_token)
        
        # Verify the dangerous patterns are not present
        dangerous_patterns = [
            "TenantAccountJoin",
            "_update_request_context_with_user",
            "user_logged_in.send",
            "Login admin"
        ]
        
        for pattern in dangerous_patterns:
            assert pattern not in source, f"Dangerous pattern '{pattern}' found in API token validation"
    
    def test_password_hashing_uses_proper_salt(self):
        """Verify password hashing uses cryptographically secure salts"""
        from api.services.account_service import AccountService
        
        with patch('api.services.account_service.secrets.token_bytes') as mock_token_bytes, \
             patch('api.services.account_service.hash_password') as mock_hash, \
             patch('api.services.account_service.db'), \
             patch('api.services.account_service.compare_password', return_value=True):
            
            mock_token_bytes.return_value = b'secure_random_salt'
            mock_hash.return_value = b'hashed_password'
            
            mock_account = MagicMock()
            mock_account.password = "old_password"
            
            AccountService.update_account_password(mock_account, "old", "new")
            
            # Verify secure random salt generation
            mock_token_bytes.assert_called_with(16)


if __name__ == "__main__":
    # Instructions for running these tests
    print("""
    Security Tests for Dify Authentication Fixes
    
    To run these tests:
    1. Copy this file to api/tests/unit_tests/security/
    2. Run: uv run --project api pytest api/tests/unit_tests/security/test_security_fixes.py
    
    These tests validate the security fixes:
    - API Token Authentication bypass prevention
    - Password reset persistence 
    - Account profile update persistence
    """)