#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

from pynamodb.attributes import (
    BooleanAttribute,
    ListAttribute,
    MapAttribute,
    UnicodeAttribute,
)

from ..model import BaseModel


class OperationMap(MapAttribute):
    query = ListAttribute()
    mutation = ListAttribute()


class ConfigMap(MapAttribute):
    class_name = UnicodeAttribute()
    funct_type = UnicodeAttribute()
    methods = ListAttribute()
    module_name = UnicodeAttribute()
    setting = UnicodeAttribute()
    auth_required = BooleanAttribute(default=False)
    graphql = BooleanAttribute(default=False)
    operations = OperationMap()


class FunctionModel(BaseModel):
    class Meta(BaseModel.Meta):
        table_name = "se-functions"

    aws_lambda_arn = UnicodeAttribute(hash_key=True)
    function = UnicodeAttribute(range_key=True)
    area = UnicodeAttribute()
    config = ConfigMap()
