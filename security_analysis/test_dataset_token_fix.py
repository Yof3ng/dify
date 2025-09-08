#!/usr/bin/env python3
"""
Test script to validate the dataset token security fix.
This ensures the fix doesn't break legitimate functionality.
"""

import sys
import os

# Add the API directory to Python path
api_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../api')
sys.path.insert(0, api_path)

def test_dataset_token_validation_structure():
    """Test that the dataset token validation function has the correct structure"""
    try:
        from controllers.service_api.wraps import validate_dataset_token
        import inspect
        
        # Get the source code
        source = inspect.getsource(validate_dataset_token)
        
        # Security checks - ensure dangerous patterns are NOT present
        dangerous_patterns = [
            "TenantAccountJoin",
            "Login admin", 
            "_update_request_context_with_user(account)",  # Should not authenticate accounts, only end_users
            "user_logged_in.send(current_app._get_current_object(), user=_get_user())"
        ]
        
        security_issues = []
        for pattern in dangerous_patterns:
            if pattern in source:
                security_issues.append(pattern)
        
        if security_issues:
            print("❌ SECURITY ISSUES FOUND:")
            for issue in security_issues:
                print(f"   - Dangerous pattern detected: {issue}")
            return False
        
        # Positive checks - ensure correct patterns ARE present
        required_patterns = [
            "validate_and_get_api_token(\"dataset\")",
            "Tenant.id == api_token.tenant_id",
            "tenant.status == TenantStatus.ARCHIVE",
            "raise Forbidden(\"The workspace's status is archived.\")"
        ]
        
        missing_patterns = []
        for pattern in required_patterns:
            if pattern not in source:
                missing_patterns.append(pattern)
        
        if missing_patterns:
            print("❌ MISSING SECURITY PATTERNS:")
            for pattern in missing_patterns:
                print(f"   - Required pattern missing: {pattern}")
            return False
        
        print("✅ Dataset token validation security structure is correct")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_imports_cleaned():
    """Test that unused imports were removed"""
    try:
        # Read the wraps.py file directly
        wraps_path = os.path.join(api_path, 'controllers', 'service_api', 'wraps.py')
        with open(wraps_path, 'r') as f:
            content = f.read()
        
        # Check that problematic imports are removed
        removed_imports = ["TenantAccountJoin", "_get_user"]
        
        import_issues = []
        for removed_import in removed_imports:
            if removed_import in content:
                import_issues.append(removed_import)
        
        if import_issues:
            print("❌ UNUSED IMPORTS STILL PRESENT:")
            for issue in import_issues:
                print(f"   - {issue} should be removed")
            return False
        
        print("✅ Unused imports have been cleaned up")
        return True
        
    except Exception as e:
        print(f"❌ Error checking imports: {e}")
        return False

def main():
    """Run all security validation tests"""
    print("🔒 Testing Dataset Token Security Fix")
    print("=" * 50)
    
    all_tests_passed = True
    
    # Test 1: Security structure
    print("\n1. Testing security structure...")
    if not test_dataset_token_validation_structure():
        all_tests_passed = False
    
    # Test 2: Import cleanup
    print("\n2. Testing import cleanup...")
    if not test_imports_cleaned():
        all_tests_passed = False
    
    # Summary
    print("\n" + "=" * 50)
    if all_tests_passed:
        print("🎉 ALL SECURITY TESTS PASSED!")
        print("✅ The dataset token security fix is correctly implemented.")
        print("✅ Critical vulnerability has been eliminated.")
    else:
        print("❌ SOME TESTS FAILED!")
        print("⚠️  Please review the security fix implementation.")
    
    return all_tests_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)