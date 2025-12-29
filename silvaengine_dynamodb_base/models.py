#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Base model classes for DynamoDB operations.

This module provides base model classes and mixins for interacting
with DynamoDB, including raw data retrieval functionality.

Example:
    >>> from silvaengine_dynamodb_base import BaseModel, RawDataMixin
    >>>
    >>> class MyModel(RawDataMixin, BaseModel):
    ...     class Meta:
    ...         table_name = 'my_table'
    ...         hash_key = 'id'
    ...     id: UnicodeAttribute = UnicodeAttribute(hash_key=True)
    ...     name: UnicodeAttribute = UnicodeAttribute()
"""

from __future__ import print_function

__author__ = "bibow"

import logging
import os
import threading
from typing import Any, Dict, List, Optional, Type, TypeVar

from pynamodb.attributes import Attribute
from pynamodb.connection import Connection
from pynamodb.exceptions import DoesNotExist
from pynamodb.models import Model

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="RawDataMixin")


class BaseModel(Model):
    """
    Base model class for DynamoDB models.

    This class extends Pynamodb's Model class with custom Meta configuration.
    """

    class Meta:
        region: Optional[str] = os.getenv("REGIONNAME")
        billing_mode: str = "PAY_PER_REQUEST"


class RawDataMixin:
    """
    Mixin class providing raw data retrieval functionality for DynamoDB models.

    This mixin provides methods for getting raw DynamoDB data without the
    overhead of Pynamodb model instantiation. It is useful when you need
    direct access to the raw DynamoDB response data.

    Note:
        This mixin must be used with a class that inherits from BaseModel
        and has proper hash_key and range_key attributes defined.

    Example:
        >>> class MyModel(RawDataMixin, BaseModel):
        ...     class Meta:
        ...         table_name = 'my_table'
        ...         hash_key = 'id'
        ...     id: UnicodeAttribute = UnicodeAttribute(hash_key=True)
        ...     name: UnicodeAttribute = UnicodeAttribute()
        >>>
        >>> # Get raw data
        >>> result = MyModel.get_raw('item-1')
        >>> item = result['item']
    """

    _connection: Optional[Connection] = None
    _connection_lock: threading.Lock = threading.Lock()

    @classmethod
    def get_raw(
        cls: Type[T],
        hash_key: Any,
        range_key: Optional[Any] = None,
        consistent_read: bool = False,
    ) -> Dict[str, Any]:
        """
        Get raw DynamoDB item data.

        Retrieves a single item from DynamoDB and returns the raw response
        including the item data, consumed capacity, and response metadata.

        Args:
            hash_key: The hash key value of the item to retrieve
            range_key: The range key value (optional, only for composite keys)
            consistent_read: Whether to use strongly consistent read (default: False)

        Returns:
            A dictionary containing:
                - item: The raw DynamoDB item data (dict)
                - consumed_capacity: Capacity units consumed (dict)
                - response_metadata: AWS response metadata (dict)

        Raises:
            DoesNotExist: If the item with the specified key does not exist
            ConnectionError: If unable to connect to DynamoDB
            Exception: For other AWS-related errors

        Example:
            >>> result = MyModel.get_raw('user-123')
            >>> item = result['item']
        """
        conn = cls._get_connection()
        key = cls._build_key(hash_key, range_key)

        try:
            response = conn.client.get_item(
                TableName=str(cls.Meta.table_name),
                Key=key,
                ConsistentRead=consistent_read,
                ReturnConsumedCapacity="TOTAL",
            )

            item = response.get("Item")
            if not item:
                raise DoesNotExist(f"Item with key {hash_key} does not exist")

            return {
                "item": item,
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }

        except DoesNotExist:
            raise
        except Exception as e:
            logger.error(f"Error getting raw item: {e}", exc_info=True)
            raise

    @classmethod
    def scan_raw(
        cls: Type[T],
        limit: Optional[int] = None,
        filter_expression: Optional[Any] = None,
        expression_attribute_names: Optional[Dict[str, str]] = None,
        expression_attribute_values: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Scan table to get raw data.

        Performs a scan operation on the DynamoDB table and returns
        the raw response including all items and metadata.

        Args:
            limit: Maximum number of items to return (optional)
            filter_expression: Filter condition for the scan (optional)
            expression_attribute_names: Attribute name mappings (optional)
            expression_attribute_values: Attribute value mappings (optional)
            **kwargs: Additional parameters passed to the scan operation

        Returns:
            A dictionary containing:
                - items: List of raw DynamoDB items
                - count: Number of items returned
                - scanned_count: Number of items scanned
                - last_evaluated_key: Key for pagination (if applicable)
                - consumed_capacity: Capacity units consumed (dict)
                - response_metadata: AWS response metadata (dict)

        Example:
            >>> result = MyModel.scan_raw(limit=100)
            >>> items = result['items']
        """
        conn = cls._get_connection()

        scan_kwargs: Dict[str, Any] = {
            "TableName": str(cls.Meta.table_name),
            "ReturnConsumedCapacity": "TOTAL",
        }

        if limit is not None:
            scan_kwargs["Limit"] = limit
        if filter_expression is not None:
            scan_kwargs["FilterExpression"] = filter_expression
        if expression_attribute_names is not None:
            scan_kwargs["ExpressionAttributeNames"] = expression_attribute_names
        if expression_attribute_values is not None:
            scan_kwargs["ExpressionAttributeValues"] = expression_attribute_values

        scan_kwargs.update(kwargs)

        try:
            response = conn.client.scan(**scan_kwargs)

            return {
                "items": response.get("Items", []),
                "count": response.get("Count", 0),
                "scanned_count": response.get("ScannedCount", 0),
                "last_evaluated_key": response.get("LastEvaluatedKey"),
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }
        except Exception as e:
            logger.error(f"Error scanning table: {e}", exc_info=True)
            raise

    @classmethod
    def query_raw(
        cls: Type[T],
        hash_key: Any,
        range_key_condition: Optional[str] = None,
        index_name: Optional[str] = None,
        limit: Optional[int] = None,
        scan_index_forward: Optional[bool] = None,
        filter_expression: Optional[Any] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Query table to get raw data.

        Performs a query operation on the DynamoDB table and returns
        the raw response including all items and metadata.

        Args:
            hash_key: The hash key value for the query
            range_key_condition: Condition for the range key (optional)
            index_name: Name of the index to query (optional)
            limit: Maximum number of items to return (optional)
            scan_index_forward: Sort order (True for ascending, False for descending)
            filter_expression: Filter condition for the query (optional)
            **kwargs: Additional parameters passed to the query operation

        Returns:
            A dictionary containing:
                - items: List of raw DynamoDB items
                - count: Number of items returned
                - scanned_count: Number of items scanned
                - last_evaluated_key: Key for pagination (if applicable)
                - consumed_capacity: Capacity units consumed (dict)
                - response_metadata: AWS response metadata (dict)

        Example:
            >>> result = MyModel.query_raw('partition-key', limit=50)
            >>> items = result['items']
        """
        conn = cls._get_connection()

        key_condition = f"#{cls._hash_keyname} = :hash_val"
        expression_attribute_names = {f"#{cls._hash_keyname}": cls._hash_keyname}
        expression_attribute_values = {
            ":hash_val": {cls._hash_key_attribute.attr_type: str(hash_key)}
        }

        if range_key_condition and cls._range_keyname:
            key_condition += f" AND {range_key_condition}"

        query_kwargs: Dict[str, Any] = {
            "TableName": str(cls.Meta.table_name),
            "KeyConditionExpression": key_condition,
            "ExpressionAttributeNames": expression_attribute_names,
            "ExpressionAttributeValues": expression_attribute_values,
            "ReturnConsumedCapacity": "TOTAL",
        }

        if index_name is not None:
            query_kwargs["IndexName"] = index_name
        if limit is not None:
            query_kwargs["Limit"] = limit
        if scan_index_forward is not None:
            query_kwargs["ScanIndexForward"] = scan_index_forward
        if filter_expression is not None:
            query_kwargs["FilterExpression"] = filter_expression

        query_kwargs.update(kwargs)

        try:
            response = conn.client.query(**query_kwargs)

            return {
                "items": response.get("Items", []),
                "count": response.get("Count", 0),
                "scanned_count": response.get("ScannedCount", 0),
                "last_evaluated_key": response.get("LastEvaluatedKey"),
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }
        except Exception as e:
            logger.error(f"Error querying table: {e}", exc_info=True)
            raise

    @classmethod
    def batch_get_raw(
        cls: Type[T],
        keys: List[Dict[str, Any]],
        consistent_read: bool = False,
    ) -> Dict[str, Any]:
        """
        Batch get raw items from DynamoDB.

        Retrieves multiple items from DynamoDB in a single batch operation.

        Args:
            keys: List of dictionaries containing hash_key and optionally range_key
            consistent_read: Whether to use strongly consistent read (default: False)

        Returns:
            A dictionary containing:
                - items: List of raw DynamoDB items
                - unprocessed_keys: Keys that were not processed (list)
                - consumed_capacity: Capacity units consumed (dict)
                - response_metadata: AWS response metadata (dict)

        Example:
            >>> keys = [
            ...     {'hash_key': 'item-1'},
            ...     {'hash_key': 'item-2', 'range_key': 'sub-key'}
            ... ]
            >>> result = MyModel.batch_get_raw(keys)
        """
        conn = cls._get_connection()

        request_items = {}
        keys_and_attributes_list = []

        for key_dict in keys:
            hash_key = key_dict.get("hash_key")
            range_key = key_dict.get("range_key")
            key = cls._build_key(hash_key, range_key)
            keys_and_attributes_list.append(key)

        request_items[str(cls.Meta.table_name)] = {
            "Keys": keys_and_attributes_list,
            "ConsistentRead": consistent_read,
        }

        try:
            response = conn.client.batch_get_item(RequestItems=request_items)

            return {
                "items": response.get("Responses", {}).get(
                    str(cls.Meta.table_name), []
                ),
                "unprocessed_keys": response.get("UnprocessedKeys", []),
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }
        except Exception as e:
            logger.error(f"Error in batch get: {e}", exc_info=True)
            raise

    @classmethod
    def _get_connection(cls: Type[T]) -> Connection:
        """
        Get or create a connection object for DynamoDB.

        This method implements a thread-safe singleton pattern for the
        connection object to avoid creating multiple connections.

        Args:
            None

        Returns:
            Connection: A Pynamodb Connection object

        Note:
            The connection is stored per-class to support inheritance.
        """
        if not hasattr(cls, "_connection") or cls._connection is None:
            with cls._connection_lock:
                if not hasattr(cls, "_connection") or cls._connection is None:
                    cls._connection = Connection(region=cls.Meta.region)
        return cls._connection

    @classmethod
    def _build_key(
        cls: Type[T],
        hash_key: Any,
        range_key: Optional[Any] = None,
    ) -> Dict[str, Dict[str, str]]:
        """
        Build a DynamoDB key dictionary from hash and range keys.

        Args:
            hash_key: The hash key value
            range_key: The range key value (optional)

        Returns:
            A dictionary representing the DynamoDB key structure

        Example:
            >>> key = cls._build_key('user-123', 'profile')
            >>> # Returns: {'id': {'S': 'user-123'}, 'sort_key': {'S': 'profile'}}
        """
        key: Dict[str, Dict[str, str]] = {
            cls._hash_keyname: {
                cls._hash_key_attribute.attr_type: str(hash_key)
            }
        }

        if range_key is not None and cls._range_keyname is not None:
            key[cls._range_keyname] = {
                cls._range_key_attribute.attr_type: str(range_key)
            }

        return key
