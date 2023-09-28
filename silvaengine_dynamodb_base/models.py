#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import print_function

__author__ = "bibow"

import os
from pynamodb.models import Model


class BaseModel(Model):
    class Meta:
        region = os.getenv("REGIONNAME")
        billing_mode = "PAY_PER_REQUEST"
