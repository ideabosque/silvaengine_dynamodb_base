#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

from typing import Any, Dict

import pendulum
from pynamodb.attributes import UnicodeAttribute, UTCDateTimeAttribute
from pynamodb.indexes import AllProjection, GlobalSecondaryIndex
from pynamodb.pagination import ResultIterator
from silvaengine_constants import SwitchStatus

from ..model import BaseModel


class GraphqlSchemaModel(BaseModel):
    class Meta(BaseModel.Meta):
        table_name = "se-graphql-schemas"

    endpoint_id = UnicodeAttribute(hash_key=True)
    operation = UnicodeAttribute(range_key=True)
    schema = UnicodeAttribute()
    module_name = UnicodeAttribute()
    class_name = UnicodeAttribute()
    created_at = UTCDateTimeAttribute()
    updated_at = UTCDateTimeAttribute()

    @classmethod
    def _build_range_key(cls, operation_type: str, operation_name: str) -> str:
        if not all([operation_type, operation_name]):
            raise ValueError("Invalid `operation_type` or `operation_name`")

        return f"{operation_type.strip().lower()}#{operation_name.strip().lower()}"

    @classmethod
    def store(
        cls,
        endpoint_id: str,
        operation_type: str,
        operation_name: str,
        schema: str,
        module_name: str,
        class_name: str,
    ) -> Dict[str, Any]:
        """Save a graphql schema model to DynamoDB."""
        try:
            if not all(
                [
                    endpoint_id,
                    operation_type,
                    operation_name,
                    schema,
                    module_name,
                    class_name,
                ]
            ):
                raise ValueError("Invalid arguments")

            now = pendulum.now("UTC")

            return GraphqlSchemaModel(
                endpoint_id.strip().lower(),
                cls._build_range_key(operation_type, operation_name),
                **{
                    "schema": schema.strip(),
                    "module_name": module_name.strip(),
                    "class_name": class_name.strip(),
                    "updated_at": now,
                    "created_at": now,
                },
            ).save()
        except Exception as e:
            raise ValueError(f"Failed to save graphql schema: {str(e)}")

    @classmethod
    def fetch(
        cls, endpoint_id: str, operation_type: str, operation_name: str
    ) -> "GraphqlSchemaModel":
        """Get a graphql schema model from DynamoDB."""
        if not all([endpoint_id, operation_type, operation_name]):
            raise ValueError(
                "Invalid `endpoint_id`, `operation_type` or `operation_name`"
            )

        try:
            return GraphqlSchemaModel.get(
                hash_key=endpoint_id,
                range_key=cls._build_range_key(operation_type, operation_name),
            )
        except Exception as e:
            raise ValueError(f"Failed to get graphql schema: {str(e)}")
