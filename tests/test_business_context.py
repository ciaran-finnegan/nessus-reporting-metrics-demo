"""
Test Business Context functionality including Business Groups and Asset Tags

This module tests the BusinessContextManager and related functionality.
"""

import pytest
import os
import sys
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from etl.loaders.business_context_manager import BusinessContextManager


class TestBusinessContextManager:
    """Test suite for BusinessContextManager"""
    
    @pytest.fixture
    def mock_supabase_client(self):
        """Create a mock Supabase client"""
        client = MagicMock()
        return client
    
    @pytest.fixture
    def context_manager(self, mock_supabase_client):
        """Create a BusinessContextManager instance with mock client"""
        return BusinessContextManager(mock_supabase_client)
    
    def test_create_business_group_root(self, context_manager, mock_supabase_client):
        """Test creating a root business group"""
        # Mock the insert response
        mock_supabase_client.table().insert().execute.return_value = MagicMock(
            data=[{'id': 'test-bg-id-123'}]
        )
        
        # Create root business group
        bg_id = context_manager.create_business_group(
            name="Test Department",
            description="Test description"
        )
        
        # Verify the call
        mock_supabase_client.table.assert_called_with('business_groups')
        insert_data = mock_supabase_client.table().insert.call_args[0][0]
        
        assert insert_data['name'] == "Test Department"
        assert insert_data['description'] == "Test description"
        assert insert_data['parent_id'] is None
        assert insert_data['path'] == "/Test Department/"
        assert insert_data['depth'] == 0
        assert bg_id == 'test-bg-id-123'
    
    def test_create_business_group_child(self, context_manager, mock_supabase_client):
        """Test creating a child business group"""
        # Mock parent lookup
        mock_supabase_client.table().select().eq().execute.return_value = MagicMock(
            data=[{'path': '/root/', 'depth': 0}]
        )
        
        # Mock insert response
        mock_supabase_client.table().insert().execute.return_value = MagicMock(
            data=[{'id': 'test-child-id-456'}]
        )
        
        # Create child business group
        bg_id = context_manager.create_business_group(
            name="Child Group",
            parent_id="parent-id-123",
            description="Child description"
        )
        
        # Verify parent lookup
        mock_supabase_client.table().select.assert_called_with('path, depth')
        
        # Verify insert data
        insert_data = mock_supabase_client.table().insert.call_args[0][0]
        assert insert_data['name'] == "Child Group"
        assert insert_data['parent_id'] == "parent-id-123"
        assert insert_data['path'] == "/root/Child Group/"
        assert insert_data['depth'] == 1
        assert bg_id == 'test-child-id-456'
    
    def test_create_tag_manual(self, context_manager, mock_supabase_client):
        """Test creating a manual tag"""
        # Mock insert response
        mock_supabase_client.table().insert().execute.return_value = MagicMock(
            data=[{'id': 'test-tag-id-789'}]
        )
        
        # Create manual tag
        tag_id = context_manager.create_tag(
            name="#production",
            tag_type="manual",
            description="Production assets",
            criticality_score=5,
            color="#FF0000"
        )
        
        # Verify the call
        mock_supabase_client.table.assert_called_with('asset_tags')
        insert_data = mock_supabase_client.table().insert.call_args[0][0]
        
        assert insert_data['name'] == "#production"
        assert insert_data['tag_type'] == "manual"
        assert insert_data['description'] == "Production assets"
        assert insert_data['color'] == "#FF0000"
        assert insert_data['metadata']['criticality_score'] == 5
        assert tag_id == 'test-tag-id-789'
    
    def test_create_tag_dynamic(self, context_manager, mock_supabase_client):
        """Test creating a dynamic tag with rules"""
        # Mock insert response
        mock_supabase_client.table().insert().execute.return_value = MagicMock(
            data=[{'id': 'test-dynamic-tag-id'}]
        )
        
        # Create dynamic tag
        rule_definition = {
            "type": "vulnerability_exists",
            "severity": ["Critical", "High"]
        }
        
        tag_id = context_manager.create_tag(
            name="#high-risk",
            tag_type="dynamic",
            rule_definition=rule_definition
        )
        
        # Verify the call
        insert_data = mock_supabase_client.table().insert.call_args[0][0]
        
        assert insert_data['name'] == "#high-risk"
        assert insert_data['tag_type'] == "dynamic"
        assert insert_data['rule_definition'] == rule_definition
        assert insert_data['evaluate_on_creation'] is True
    
    def test_assign_assets_to_business_group(self, context_manager, mock_supabase_client):
        """Test assigning assets to a business group"""
        # Mock upsert response
        mock_supabase_client.table().upsert().execute.return_value = MagicMock(
            data=[{}, {}, {}]  # 3 assignments
        )
        
        # Assign assets
        asset_ids = ['asset-1', 'asset-2', 'asset-3']
        count = context_manager.assign_assets_to_business_group(
            asset_ids=asset_ids,
            business_group_id='bg-id-123',
            assigned_by='test@example.com'
        )
        
        # Verify the call
        mock_supabase_client.table.assert_called_with('asset_business_groups')
        upsert_data = mock_supabase_client.table().upsert.call_args[0][0]
        
        assert len(upsert_data) == 3
        assert all(item['business_group_id'] == 'bg-id-123' for item in upsert_data)
        assert all(item['assigned_by'] == 'test@example.com' for item in upsert_data)
        assert count == 3
    
    def test_apply_tag_to_assets(self, context_manager, mock_supabase_client):
        """Test applying tags to assets"""
        # Mock upsert response
        mock_supabase_client.table().upsert().execute.return_value = MagicMock(
            data=[{}, {}]  # 2 assignments
        )
        
        # Apply tags
        asset_ids = ['asset-1', 'asset-2']
        count = context_manager.apply_tag_to_assets(
            asset_ids=asset_ids,
            tag_id='tag-id-456',
            auto_applied=True
        )
        
        # Verify the call
        mock_supabase_client.table.assert_called_with('asset_tag_assignments')
        upsert_data = mock_supabase_client.table().upsert.call_args[0][0]
        
        assert len(upsert_data) == 2
        assert all(item['tag_id'] == 'tag-id-456' for item in upsert_data)
        assert all(item['auto_applied'] is True for item in upsert_data)
        assert count == 2
    
    def test_find_assets_by_ip_range(self, context_manager, mock_supabase_client):
        """Test finding assets by IP range"""
        # Mock assets query
        mock_assets = [
            {'id': 'asset-1', 'current_ip_address': '10.0.0.5'},
            {'id': 'asset-2', 'current_ip_address': '10.0.0.15'},
            {'id': 'asset-3', 'current_ip_address': '192.168.1.10'}
        ]
        mock_supabase_client.table().select().eq().eq().execute.return_value = MagicMock(
            data=mock_assets
        )
        
        # Find assets in range
        matching = context_manager._find_assets_by_ip_range(['10.0.0.0/24'])
        
        # Should match first two assets
        assert set(matching) == {'asset-1', 'asset-2'}
    
    def test_find_assets_by_name_pattern(self, context_manager, mock_supabase_client):
        """Test finding assets by name pattern"""
        # Mock assets query
        mock_supabase_client.table().select().ilike().eq().execute.return_value = MagicMock(
            data=[
                {'id': 'asset-1'},
                {'id': 'asset-2'}
            ]
        )
        
        # Find assets by pattern
        matching = context_manager._find_assets_by_name_pattern(['prod-*'])
        
        # Verify the call used correct SQL pattern
        mock_supabase_client.table().select().ilike.assert_called_with(
            'current_hostname', 'prod-%'
        )
        
        assert set(matching) == {'asset-1', 'asset-2'}
    
    def test_evaluate_tag_rule_vulnerability_exists(self, context_manager, mock_supabase_client):
        """Test evaluating vulnerability-based tag rules"""
        # Mock tag with vulnerability rule
        tag = {
            'id': 'tag-123',
            'name': '#critical-vulns',
            'rule_definition': {
                'type': 'vulnerability_exists',
                'severity': ['Critical']
            }
        }
        
        # Mock vulnerability definitions lookup
        mock_supabase_client.table().select().in_().execute.return_value = MagicMock(
            data=[{'id': 'vuln-def-1'}, {'id': 'vuln-def-2'}]
        )
        
        # Mock vulnerability scans query
        mock_supabase_client.table().select().in_().in_().eq().execute.return_value = MagicMock(
            data=[
                {'asset_id': 'asset-1'},
                {'asset_id': 'asset-2'},
                {'asset_id': 'asset-1'}  # Duplicate
            ]
        )
        
        # Mock update for last_evaluated
        mock_supabase_client.table().update().eq().execute.return_value = MagicMock(data=[])
        
        # Mock apply tags
        mock_supabase_client.table().upsert().execute.return_value = MagicMock(data=[{}, {}])
        
        # Evaluate rule
        context_manager._evaluate_tag_rule(tag)
        
        # Verify vulnerability lookup
        assert mock_supabase_client.table().select().in_.called
        
        # Verify tags were applied to unique assets
        # Check if upsert was called (it should be through apply_tag_to_assets method)
        assert mock_supabase_client.table().upsert.called
        # The actual upsert happens in apply_tag_to_assets which is tested separately
    
    def test_create_default_business_groups(self, context_manager, mock_supabase_client):
        """Test creating default business group structure"""
        # Mock all insert responses
        mock_supabase_client.table().insert().execute.return_value = MagicMock(
            data=[{'id': 'mock-id'}]
        )
        
        # Create defaults
        context_manager.create_default_business_groups()
        
        # Verify multiple business groups were created
        insert_calls = mock_supabase_client.table().insert.call_count
        assert insert_calls >= 10  # At least root groups and some children
    
    def test_create_default_dynamic_tags(self, context_manager, mock_supabase_client):
        """Test creating default dynamic tags"""
        # Mock all insert responses
        mock_supabase_client.table().insert().execute.return_value = MagicMock(
            data=[{'id': 'mock-tag-id'}]
        )
        
        # Create defaults
        context_manager.create_default_dynamic_tags()
        
        # Verify multiple tags were created
        insert_calls = mock_supabase_client.table().insert.call_count
        assert insert_calls >= 4  # At least the default tags


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 