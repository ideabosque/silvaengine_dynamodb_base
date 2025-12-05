#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import pendulum
import pynamodb
from silvaengine_utility import Utility
from boto3.dynamodb.conditions import Key
from typing import Any, Dict, Tuple, List
from .models import BaseModel, EndpointModel, ConnectionModel, FunctionModel, HookModel, ConfigModel, WSSConnectionModel


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

    @staticmethod
    def get_hooks(api_id: str) -> List[Dict[str, Any]]:
        """
        Fetch active hooks for a given API ID.
        :param api_id: The ID of the API.
        :return: A list of hooks.
        """
        if not api_id:
            return {}
        
        try:
            return [
                {item.variable: item.value}
                for item in HookModel.query(api_id, None, HookModel.status.is_(True))
            ]
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Failed to get hooks for API {api_id}: {str(e)}")
    
    @staticmethod
    def get_setting(setting_id: str) -> Dict[str, Any]:
        """
        Fetch a setting from DynamoDB based on the setting ID with caching.
        :param setting_id: The ID of the setting.
        :return: A dictionary of settings.
        """
        if not setting_id:
            return {}
        
        try:
            return [
                {item.variable: item.value}
                for item in ConfigModel.query(setting_id)
            ]

        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Failed to get setting {setting_id}: {str(e)}")
    
    @staticmethod
    def get_function(
        endpoint_id: str, function_name: str, api_key: str = "#####", method: str = None
    ) -> Tuple[Dict[str, Any], FunctionModel]:
        """
        Fetch the function configuration for a given endpoint with caching.
        :param endpoint_id: ID of the endpoint.
        :param funct: Name of the function to retrieve.
        :param api_key: The API key, default is "#####".
        :param method: The HTTP method if applicable.
        :return: A tuple containing the merged settings and the function object.
        """
        if not function_name:
            raise ValueError("Function name is required")
        
        try:
            effective_endpoint_id = endpoint_id
            if endpoint_id != "0":
                try:
                    endpoint = EndpointModel.get(endpoint_id)
                    if not endpoint.special_connection:
                        effective_endpoint_id = "1"
                except Exception:
                    effective_endpoint_id = "1"
            else:
                effective_endpoint_id = "1"

            connection = ConnectionModel.get(effective_endpoint_id, api_key)
            functions = next((f for f in connection.functions if f.function == function_name), None)

            if not functions:
                raise ValueError(
                    f"Cannot find the function({function_name}) with endpoint_id({effective_endpoint_id}) and api_key({api_key})."
                )

            function = FunctionModel.get(
                functions.aws_lambda_arn, functions.function
            )

            if function is None:
                raise ValueError(
                    "Cannot locate the function!! Please check the path and parameters."
                )

            if method and method not in function.config.methods:
                raise ValueError(
                    f"The function({function_name}) doesn't support the method({method})."
                )

            # Merge settings from connection and function, connection settings override function settings
            function_setting = SilvaEngineDynamoDBBase.get_setting(function.config.setting) if function.config.setting else {}
            connection_setting = SilvaEngineDynamoDBBase.get_setting(functions.setting) if functions.setting else {}
            
            setting = {
                **function_setting,
                **connection_setting,
            }
 
            return setting, function
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Failed to get function {function_name}: {str(e)}")

    @staticmethod
    def save_wss_connection(endpoint_id: str, connection_id: str, api_key: str, area: str, data: dict) -> None:
        """
        Save a WSS connection model to DynamoDB.
        :param endpoint_id: The ID of the endpoint.
        :param connection_id: The ID of the connection.
        :param api_key: The API key.
        :param area: The area.
        :param data: The connection data.
        """
        try:
            WSSConnectionModel(
                endpoint_id,
                connection_id,
                **{
                    "api_key": api_key,
                    "area": area,
                    "data": data,
                    "updated_at": pendulum.now("UTC"),
                    "created_at": pendulum.now("UTC"),
                },
            ).save()
        except Exception as e:
            raise ValueError(f"Failed to save WSS connection: {str(e)}")
        
    @staticmethod
    def get_wss_connection(endpoint_id: str, connection_id: str) -> WSSConnectionModel:
        """
        Get a WSS connection model from DynamoDB.
        :param endpoint_id: The ID of the endpoint.
        :param connection_id: The ID of the connection.
        :return: The WSS connection model.
        """
        try:
            return WSSConnectionModel.get(endpoint_id, connection_id)
        except Exception as e:
            raise ValueError(f"Failed to get WSS connection: {str(e)}")
        
    @staticmethod
    def get_wss_connections_by_id(connection_id: str) -> List[WSSConnectionModel]:
        """
        Get all WSS connection models from DynamoDB for a given connection.
        :param connection_id: The ID of the connection.
        :return: A list of WSS connection models.
        """
        try:
            return WSSConnectionModel.connect_id_index.query(connection_id, None)
        except Exception as e:
            raise ValueError(f"Failed to get WSS connections: {str(e)}")
        
    @staticmethod
    def delete_inactive_wss_connections(endpoint_id: str, cutoff_time: pendulum.DateTime, email: str = None, range_condition: pynamodb.Condition = None) -> None:
        """
        Get all WSS connection models from DynamoDB for a given endpoint.
        :param endpoint_id: The ID of the endpoint.
        :param range_condition: The range key condition.
        :param cutoff_time: The cutoff time.
        :return: A list of WSS connection models.
        """
        try:
            connections = WSSConnectionModel.query(
                endpoint_id,
                range_condition,  # Range key condition
                filter_condition=WSSConnectionModel.updated_at < cutoff_time,
            )

            # Iterate through and delete matching connections
            for connection in connections:
                if (
                    email is not None
                    and connection.data.__dict__["attribute_values"].get("email") != email
                ):
                    pass

                connection.delete()
        except Exception as e:
            raise ValueError(f"Failed to get WSS connections: {str(e)}")