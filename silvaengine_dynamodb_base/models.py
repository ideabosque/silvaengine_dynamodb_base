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
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Type, TypeVar, Union

from pynamodb.attributes import Attribute
from pynamodb.connection.table import TableConnection
from pynamodb.exceptions import DoesNotExist, GetError, PutError, QueryError, ScanError
from pynamodb.models import Model

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="RawDataMixin")

DYNAMO_ATTRIBUTE_TYPES = {"S", "N", "B", "SS", "NS", "BS", "M", "L", "NULL", "BOOL"}


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

    This implementation follows Pynamodb's best practices:
    - Uses TableConnection for table-specific operations
    - Implements thread-local connection caching
    - Provides consistent return types across all operations
    - Includes comprehensive error handling and logging

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

    _connection: Optional[TableConnection] = None
    _connection_lock: threading.RLock = threading.RLock()
    _thread_local: threading.local = threading.local()

    @classmethod
    def _get_connection(cls: Type[T]) -> TableConnection:
        """
        Get or create a thread-local connection object for DynamoDB.

        This method implements a thread-safe singleton pattern using thread-local
        storage, following Pynamodb's connection management approach. Each thread
        maintains its own connection to avoid contention.

        Returns:
            TableConnection: A Pynamodb TableConnection object

        Note:
            The connection is stored per-class and per-thread to support
            both inheritance and thread safety.
        """
        thread_local_attr = f"_connection_{cls.__name__}"

        if not hasattr(cls._thread_local, thread_local_attr):
            with cls._connection_lock:
                if not hasattr(cls._thread_local, thread_local_attr):
                    cls._thread_local.__dict__[thread_local_attr] = TableConnection(
                        table_name=str(cls.Meta.table_name),
                        region=cls.Meta.region,
                        host=getattr(cls.Meta, "host", None),
                        connect_timeout_seconds=getattr(
                            cls.Meta, "connect_timeout_seconds", None
                        ),
                        read_timeout_seconds=getattr(
                            cls.Meta, "read_timeout_seconds", None
                        ),
                        max_retry_attempts=getattr(
                            cls.Meta, "max_retry_attempts", None
                        ),
                        max_pool_connections=getattr(
                            cls.Meta, "max_pool_connections", None
                        ),
                        extra_headers=getattr(cls.Meta, "extra_headers", None),
                    )

        return cls._thread_local.__dict__[thread_local_attr]

    @classmethod
    def _get_attribute_metadata(
        cls: Type[T],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Retrieve attribute metadata for the model.

        Returns a dictionary mapping attribute names to their metadata,
        including the attribute type and whether they are hash/range keys.

        Returns:
            Dict mapping attribute names to metadata dictionaries
        """
        if not hasattr(cls, "_attribute_metadata"):
            metadata = {}
            for attr_name, attr_obj in cls.get_attributes().items():
                metadata[attr_name] = {
                    "attr_type": attr_obj.attr_type,
                    "is_hash_key": attr_obj.is_hash_key,
                    "is_range_key": attr_obj.is_range_key,
                    "attr_name": attr_obj.attr_name,
                }
            cls._attribute_metadata = metadata
        return cls._attribute_metadata

    @classmethod
    def _serialize_key_value(
        cls: Type[T],
        value: Any,
        attr_type: str,
    ) -> Dict[str, Any]:
        """
        Serialize a value to DynamoDB attribute format.

        Args:
            value: The value to serialize
            attr_type: The DynamoDB attribute type (S, N, B, etc.)

        Returns:
            A dictionary with the serialized value in DynamoDB format
        """
        if attr_type == "S":
            return {"S": str(value)}
        elif attr_type == "N":
            return {"N": str(value)}
        elif attr_type == "B":
            if isinstance(value, bytes):
                return {"B": value}
            return {"B": str(value).encode("utf-8")}
        elif attr_type == "SS":
            if isinstance(value, (set, frozenset)):
                return {"SS": [str(v) for v in value]}
            return {"SS": [str(v) for v in value]}
        elif attr_type == "NS":
            if isinstance(value, (set, frozenset)):
                return {"NS": [str(v) for v in value]}
            return {"NS": [str(v) for v in value]}
        elif attr_type == "BOOL":
            return {"BOOL": bool(value)}
        elif attr_type == "NULL":
            return {"NULL": value is None}
        else:
            return {"S": str(value)}

    @classmethod
    def _build_key(
        cls: Type[T],
        hash_key: Any,
        range_key: Optional[Any] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Build a DynamoDB key dictionary from hash and range keys.

        This method properly serializes key values according to their
        attribute types, following Pynamodb's attribute serialization patterns.

        Args:
            hash_key: The hash key value
            range_key: The range key value (optional)

        Returns:
            A dictionary representing the DynamoDB key structure

        Example:
            >>> key = cls._build_key('user-123', 'profile')
            >>> # Returns: {'id': {'S': 'user-123'}, 'sort_key': {'S': 'profile'}}
        """
        attr_metadata = cls._get_attribute_metadata()

        hash_attr_type = attr_metadata.get(cls._hash_keyname, {}).get("attr_type", "S")
        key: Dict[str, Dict[str, Any]] = {
            cls._hash_keyname: cls._serialize_key_value(hash_key, hash_attr_type)
        }

        if range_key is not None and cls._range_keyname is not None:
            range_attr_type = attr_metadata.get(cls._range_keyname, {}).get(
                "attr_type", "S"
            )
            key[cls._range_keyname] = cls._serialize_key_value(
                range_key, range_attr_type
            )

        return key

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
            GetError: If unable to retrieve the item from DynamoDB
            Exception: For other AWS-related errors

        Example:
            >>> result = MyModel.get_raw('user-123')
            >>> item = result['item']
        """
        conn = cls._get_connection()
        key = cls._build_key(hash_key, range_key)

        try:
            response = conn.get_item(
                hash_key=hash_key,
                range_key=range_key,
                consistent_read=consistent_read,
                return_consumed_capacity="TOTAL",
            )

            if "Item" not in response or response["Item"] is None:
                raise DoesNotExist(f"Item with key {hash_key} does not exist")

            return {
                "item": response["Item"],
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }

        except DoesNotExist:
            raise
        except GetError as e:
            logger.error("Error getting raw item: %s", e, exc_info=True)
            raise
        except Exception as e:
            logger.error("Unexpected error getting raw item: %s", e, exc_info=True)
            raise GetError(f"Failed to get item: {e}") from e

    @classmethod
    def scan_raw(
        cls: Type[T],
        limit: Optional[int] = None,
        filter_expression: Optional[Any] = None,
        expression_attribute_names: Optional[Dict[str, str]] = None,
        expression_attribute_values: Optional[Dict[str, Any]] = None,
        index_name: Optional[str] = None,
        segment: Optional[int] = None,
        total_segments: Optional[int] = None,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
        consistent_read: bool = False,
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
            index_name: Name of the index to scan (optional)
            segment: Segment number for parallel scan (optional)
            total_segments: Total number of segments for parallel scan (optional)
            exclusive_start_key: Key to start scanning from (optional)
            consistent_read: Whether to use strongly consistent read (optional)
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

        try:
            response = conn.scan(
                filter_condition=filter_expression,
                limit=limit,
                return_consumed_capacity="TOTAL",
                segment=segment,
                total_segments=total_segments,
                exclusive_start_key=exclusive_start_key,
                consistent_read=consistent_read,
                index_name=index_name,
                attributes_to_get=expression_attribute_names,
            )

            return {
                "items": response.get("Items", []),
                "count": response.get("Count", 0),
                "scanned_count": response.get("ScannedCount", 0),
                "last_evaluated_key": response.get("LastEvaluatedKey"),
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }

        except ScanError as e:
            logger.error("Error scanning table: %s", e, exc_info=True)
            raise
        except Exception as e:
            logger.error("Unexpected error scanning table: %s", e, exc_info=True)
            raise ScanError(f"Failed to scan table: {e}") from e

    @classmethod
    def query_raw(
        cls: Type[T],
        hash_key: Any,
        range_key_condition: Optional[Any] = None,
        index_name: Optional[str] = None,
        limit: Optional[int] = None,
        scan_index_forward: Optional[bool] = None,
        filter_expression: Optional[Any] = None,
        exclusive_start_key: Optional[Dict[str, Any]] = None,
        consistent_read: bool = False,
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
            exclusive_start_key: Key to start querying from (optional)
            consistent_read: Whether to use strongly consistent read (optional)
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

        try:
            response = conn.query(
                hash_key=hash_key,
                range_key_condition=range_key_condition,
                filter_condition=filter_expression,
                index_name=index_name,
                limit=limit,
                scan_index_forward=scan_index_forward,
                exclusive_start_key=exclusive_start_key,
                consistent_read=consistent_read,
                return_consumed_capacity="TOTAL",
            )

            return {
                "items": response.get("Items", []),
                "count": response.get("Count", 0),
                "scanned_count": response.get("ScannedCount", 0),
                "last_evaluated_key": response.get("LastEvaluatedKey"),
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }

        except QueryError as e:
            logger.error("Error querying table: %s", e, exc_info=True)
            raise
        except Exception as e:
            logger.error("Unexpected error querying table: %s", e, exc_info=True)
            raise QueryError(f"Failed to query table: {e}") from e

    @classmethod
    def batch_get_raw(
        cls: Type[T],
        keys: List[Dict[str, Any]],
        consistent_read: bool = False,
        return_consumed_capacity: str = "TOTAL",
    ) -> Dict[str, Any]:
        """
        Batch get raw items from DynamoDB.

        Retrieves multiple items from DynamoDB in a single batch operation.
        This method automatically handles pagination for large result sets.

        Args:
            keys: List of dictionaries containing hash_key and optionally range_key
            consistent_read: Whether to use strongly consistent read (default: False)
            return_consumed_capacity: 'TOTAL', 'INDEXES', or 'NONE' (default: 'TOTAL')

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
        if not keys:
            return {
                "items": [],
                "unprocessed_keys": [],
                "consumed_capacity": None,
                "response_metadata": None,
            }

        conn = cls._get_connection()

        serialized_keys = []
        for key_dict in keys:
            hash_key = key_dict.get("hash_key")
            range_key = key_dict.get("range_key")
            key = cls._build_key(hash_key, range_key)
            serialized_keys.append(key)

        try:
            response = conn.batch_get_item(
                keys=serialized_keys,
                consistent_read=consistent_read,
                return_consumed_capacity=return_consumed_capacity,
            )

            return {
                "items": response.get("Responses", {}).get(cls.Meta.table_name, []),
                "unprocessed_keys": response.get("UnprocessedKeys", []),
                "consumed_capacity": response.get("ConsumedCapacity"),
                "response_metadata": response.get("ResponseMetadata"),
            }

        except GetError as e:
            logger.error("Error in batch get: %s", e, exc_info=True)
            raise
        except Exception as e:
            logger.error("Unexpected error in batch get: %s", e, exc_info=True)
            raise GetError(f"Failed to batch get items: {e}") from e

    @classmethod
    @contextmanager
    def batch_write_raw(
        cls: Type[T],
        return_consumed_capacity: str = "TOTAL",
        return_item_collection_metrics: str = "NONE",
    ) -> Iterator[Dict[str, Any]]:
        """
        Context manager for batch write operations.

        Provides a convenient interface for performing batch write operations
        with automatic commit on context exit.

        Args:
            return_consumed_capacity: 'TOTAL', 'INDEXES', or 'NONE'
            return_item_collection_metrics: 'SIZE' or 'NONE'

        Yields:
            A dictionary with 'put_items' and 'delete_items' lists

        Example:
            >>> with MyModel.batch_write_raw() as batch:
            ...     batch['put_items'].append({'id': {'S': 'new-item'}})
            ...     batch['delete_items'].append({'id': {'S': 'old-item'}})
        """
        conn = cls._get_connection()

        pending = {"put_items": [], "delete_items": []}
        result = {}

        try:
            yield pending

            put_items = [item for item in pending["put_items"] if item is not None]
            delete_items = [
                item for item in pending["delete_items"] if item is not None
            ]

            if put_items or delete_items:
                result = conn.batch_write_item(
                    put_items=put_items,
                    delete_items=delete_items,
                    return_consumed_capacity=return_consumed_capacity,
                    return_item_collection_metrics=return_item_collection_metrics,
                )

        except Exception as e:
            logger.error("Error in batch write: %s", e, exc_info=True)
            raise

    @classmethod
    def get_items_batch(
        cls: Type[T],
        keys: List[Dict[str, Any]],
        consistent_read: bool = False,
        chunksize: int = 100,
    ) -> Iterator[Dict[str, Any]]:
        """
        Generator that yields batch get results.

        Automatically handles pagination for large key sets by yielding
        results in chunks of up to 'chunksize' items.

        Args:
            keys: List of dictionaries containing hash_key and optionally range_key
            consistent_read: Whether to use strongly consistent read
            chunksize: Maximum number of keys per batch (default: 100)

        Yields:
            Batch result dictionaries containing items and metadata

        Example:
            >>> for batch in MyModel.get_items_batch(large_key_list):
            ...     for item in batch['items']:
            ...         process(item)
        """
        conn = cls._get_connection()

        for i in range(0, len(keys), chunksize):
            chunk = keys[i : i + chunksize]

            result = cls.batch_get_raw(chunk, consistent_read=consistent_read)
            yield result

            while result.get("unprocessed_keys"):
                retry_keys = result["unprocessed_keys"]
                result = cls.batch_get_raw(retry_keys, consistent_read=consistent_read)
                yield result

    @classmethod
    def scan_paginated(
        cls: Type[T],
        limit: Optional[int] = None,
        filter_expression: Optional[Any] = None,
        segment: Optional[int] = None,
        total_segments: Optional[int] = None,
        **kwargs: Any,
    ) -> Iterator[Dict[str, Any]]:
        """
        Generator that yields scan results with automatic pagination.

        Handles pagination automatically by yielding items from all pages
        until the limit is reached or the scan is complete.

        Args:
            limit: Maximum total items to return (optional)
            filter_expression: Filter condition for the scan (optional)
            segment: Segment number for parallel scan (optional)
            total_segments: Total number of segments for parallel scan (optional)
            **kwargs: Additional scan parameters

        Yields:
            Item dictionaries from the scan results

        Example:
            >>> for item in MyModel.scan_paginated(limit=1000):
            ...     process(item)
        """
        conn = cls._get_connection()

        exclusive_start_key = None
        total_count = 0

        while limit is None or total_count < limit:
            response = conn.scan(
                filter_condition=filter_expression,
                limit=limit - total_count if limit else None,
                exclusive_start_key=exclusive_start_key,
                segment=segment,
                total_segments=total_segments,
                return_consumed_capacity="TOTAL",
            )

            items = response.get("Items", [])
            for item in items:
                if limit and total_count >= limit:
                    break
                yield item
                total_count += 1

            exclusive_start_key = response.get("LastEvaluatedKey")
            if not exclusive_start_key:
                break

    @classmethod
    def query_paginated(
        cls: Type[T],
        hash_key: Any,
        range_key_condition: Optional[Any] = None,
        index_name: Optional[str] = None,
        limit: Optional[int] = None,
        scan_index_forward: Optional[bool] = None,
        filter_expression: Optional[Any] = None,
        consistent_read: bool = False,
        **kwargs: Any,
    ) -> Iterator[Dict[str, Any]]:
        """
        Generator that yields query results with automatic pagination.

        Handles pagination automatically by yielding items from all pages
        until the limit is reached or the query is complete.

        Args:
            hash_key: The hash key value for the query
            range_key_condition: Condition for the range key (optional)
            index_name: Name of the index to query (optional)
            limit: Maximum total items to return (optional)
            scan_index_forward: Sort order (True for ascending, False for descending)
            filter_expression: Filter condition for the query (optional)
            consistent_read: Whether to use strongly consistent read
            **kwargs: Additional query parameters

        Yields:
            Item dictionaries from the query results

        Example:
            >>> for item in MyModel.query_paginated('partition-key', limit=100):
            ...     process(item)
        """
        conn = cls._get_connection()

        exclusive_start_key = None
        total_count = 0

        while limit is None or total_count < limit:
            response = conn.query(
                hash_key=hash_key,
                range_key_condition=range_key_condition,
                index_name=index_name,
                limit=limit - total_count if limit else None,
                scan_index_forward=scan_index_forward,
                filter_condition=filter_expression,
                exclusive_start_key=exclusive_start_key,
                consistent_read=consistent_read,
                return_consumed_capacity="TOTAL",
            )

            items = response.get("Items", [])
            for item in items:
                if limit and total_count >= limit:
                    break
                yield item
                total_count += 1

            exclusive_start_key = response.get("LastEvaluatedKey")
            if not exclusive_start_key:
                break
