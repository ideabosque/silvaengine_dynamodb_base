#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

from typing import Any, Dict, List

from pynamodb.attributes import UnicodeAttribute

from ..model import AnyAttribute, BaseModel


class ConfigModel(BaseModel):
    class Meta(BaseModel.Meta):
        abstract = True
        table_name = "se-configdata"

    setting_id = UnicodeAttribute(hash_key=True)
    variable = UnicodeAttribute()
    value = AnyAttribute()

    @classmethod
    def find(
        cls,
        setting_id: str,
        return_dict: bool = True,
    ) -> Dict[str, Any] | List[BaseModel]:
        """
        Fetch a setting from DynamoDB based on the setting ID with caching.
        :param setting_id: The ID of the setting.
        :return: A dictionary of settings.
        """
        setting_id = str(setting_id).strip()

        if not setting_id:
            return []

        try:
            result = cls.query_raw(hash_key=setting_id)

            if result.get("Count", 0) < 1:
                raise ValueError(
                    f"Cannot find values with the setting_id ({setting_id})."
                )

            items = result.get("Items", [])

            if len(items) < 1:
                return []
            elif return_dict:
                return cls.boto3_items_to_dict_list(items)

            return cls.boto3_items_to_models(items)
        except Exception as e:
            if isinstance(e, ValueError):
                raise e
            raise ValueError(f"Failed to get setting {setting_id}: {str(e)}")
