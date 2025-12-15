#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

from silvaengine_utility import Utility, convert_decimal_to_number

from .models import BaseModel


class SilvaEngineDynamoDBBase(object):
    def __init__(self, logger, **setting):
        self.logger = logger
        self.setting = setting

        if (
            setting.get("region_name")
            and setting.get("aws_access_key_id")
            and setting.get("aws_secret_access_key")
        ):
            BaseModel.Meta.region = setting.get("region_name")
            BaseModel.Meta.aws_access_key_id = setting.get("aws_access_key_id")
            BaseModel.Meta.aws_secret_access_key = setting.get("aws_secret_access_key")

    def graphql_execute(self, schema, **params):
        try:
            context = {
                "logger": self.logger,
                "setting": self.setting,
                "endpoint_id": params.get("endpoint_id"),
                "connection_id": params.get("connection_id"),
            }

            if params.get("context"):
                context = dict(context, **params["context"])

            variables = convert_decimal_to_number(params.get("variables", {}))
            query = params.get("query")
            operation_name = params.get("operation_name")
            response = {
                "errors": "Invalid operations.",
                "status_code": 400,
            }

            if not query:
                return Utility.json_dumps(response)

            execution_result = schema.execute(
                query,
                context_value=context,
                variable_values=variables,
                operation_name=operation_name,
            )

            if execution_result.errors:
                response = {
                    "errors": [
                        Utility.format_error(e) for e in execution_result.errors
                    ],
                }
            elif not execution_result or execution_result.invalid:
                response = {
                    "errors": "Invalid execution result.",
                }
            elif execution_result.data:
                response = {"data": execution_result.data, "status_code": 200}
            else:
                response = {
                    "errors": "Uncaught execution error.",
                }

            return Utility.json_dumps(response)
        except Exception as e:
            raise e
