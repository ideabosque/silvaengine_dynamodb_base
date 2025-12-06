#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import os
from pynamodb.models import Model
from pynamodb.connection import Connection
from pynamodb.exceptions import DoesNotExist


class BaseModel(Model):
    class Meta:
        region = os.getenv("REGIONNAME")
        billing_mode = "PAY_PER_REQUEST"


class RawDataMixin:
    """Mixin class: Add raw data retrieval functionality"""
    
    @classmethod
    def get_raw(cls, hash_key, range_key=None, consistent_read=False):
        """
        Get raw DynamoDB data
        
        Args:
            hash_key: Hash key value
            range_key: Range key value (optional)
            consistent_read: Whether to use strongly consistent read
        
        Returns:
            dict: Raw DynamoDB data
        """
        conn = cls._get_connection()
        key = cls._build_key(hash_key, range_key)

        try:
            response = conn.client.get_item(
                TableName=cls.Meta.table_name,
                Key=key,
                ConsistentRead=consistent_read,
                ReturnConsumedCapacity='TOTAL'
            )
            
            item = response.get('Item')
            if not item:
                raise DoesNotExist(f"Item with key {key} does not exist")
            
            return {
                'item': item,
                'consumed_capacity': response.get('ConsumedCapacity'),
                'response_metadata': response.get('ResponseMetadata')
            }
            
        except Exception as e:
            raise
    
    @classmethod
    def scan_raw(cls, **kwargs):
        """
        Scan table to get raw data
        
        Args:
            **kwargs: Parameters passed to scan
        
        Returns:
            dict: Contains raw data and metadata
        """
        conn = cls._get_connection()
        
        scan_kwargs = {
            'TableName': cls.Meta.table_name,
            'ReturnConsumedCapacity': 'TOTAL'
        }

        if 'limit' in kwargs:
            scan_kwargs['Limit'] = kwargs['limit']
        if 'filter_expression' in kwargs:
            scan_kwargs['FilterExpression'] = kwargs['filter_expression']
        if 'expression_attribute_names' in kwargs:
            scan_kwargs['ExpressionAttributeNames'] = kwargs['expression_attribute_names']
        if 'expression_attribute_values' in kwargs:
            scan_kwargs['ExpressionAttributeValues'] = kwargs['expression_attribute_values']
        
        response = conn.client.scan(**scan_kwargs)
        
        return {
            'items': response.get('Items', []),
            'count': response.get('Count', 0),
            'scanned_count': response.get('ScannedCount', 0),
            'last_evaluated_key': response.get('LastEvaluatedKey'),
            'consumed_capacity': response.get('ConsumedCapacity'),
            'response_metadata': response.get('ResponseMetadata')
        }
    
    @classmethod
    def query_raw(cls, hash_key, range_key_condition=None, **kwargs):
        """
        Query raw data
        
        Args:
            hash_key: Hash key value
            range_key_condition: Range key condition
            **kwargs: Additional parameters
        
        Returns:
            dict: Query results
        """
        conn = cls._get_connection()
        key_condition = f"#{cls._hash_keyname} = :hash_val"
        expression_attribute_names = {
            f'#{cls._hash_keyname}': cls._hash_keyname
        }
        expression_attribute_values = {
            ':hash_val': {cls._hash_key_attribute.attr_type: str(hash_key)}
        }
        
        if range_key_condition and cls._range_keyname:
            key_condition += f" AND {range_key_condition}"
        
        query_kwargs = {
            'TableName': cls.Meta.table_name,
            'KeyConditionExpression': key_condition,
            'ExpressionAttributeNames': expression_attribute_names,
            'ExpressionAttributeValues': expression_attribute_values,
            'ReturnConsumedCapacity': 'TOTAL'
        }

        for key in ['IndexName', 'Limit', 'ScanIndexForward', 'FilterExpression']:
            if key in kwargs:
                query_kwargs[key] = kwargs[key]
        
        response = conn.client.query(**query_kwargs)
        
        return {
            'items': response.get('Items', []),
            'count': response.get('Count', 0),
            'scanned_count': response.get('ScannedCount', 0),
            'last_evaluated_key': response.get('LastEvaluatedKey'),
            'consumed_capacity': response.get('ConsumedCapacity')
        }
    
    @classmethod
    def _get_connection(cls):
        """Get connection object"""
        if not hasattr(cls, '_connection') or cls._connection is None:
            cls._connection = Connection(region=cls.Meta.region)
        return cls._connection
    
    @classmethod
    def _build_key(cls, hash_key, range_key=None):
        """Build DynamoDB key"""
        key = {
            cls._hash_keyname: {
                cls._hash_key_attribute.attr_type: str(hash_key)
            }
        }
        
        if range_key is not None and cls._range_keyname:
            key[cls._range_keyname] = {
                cls._range_key_attribute.attr_type: str(range_key)
            }
        
        return key
