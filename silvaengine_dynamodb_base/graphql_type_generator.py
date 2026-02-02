"""
PynamoDB to GraphQL Type Generator
Automatically converts PynamoDB models to GraphQL types
"""

import inspect
import typing
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import get_type_hints

try:
    from graphene import (
        Boolean,
        Date,
        DateTime,
        Field,
        Float,
        Int,
        List,
        NonNull,
        ObjectType,
        String,
    )
    from graphene import Decimal as GraphQLDecimal
    from graphene import Enum as GraphQLEnum
except ImportError:
    print("Please install graphene: pip install graphene")
    raise


class DataTypeMapper:
    """Maps PynamoDB types to GraphQL types"""

    TYPE_MAPPING = {
        str: String,
        int: Int,
        float: Float,
        bool: Boolean,
        datetime: DateTime,
        date: Date,
        Decimal: GraphQLDecimal,
    }

    @classmethod
    def map_type(cls, python_type):
        """Map Python type to GraphQL type"""
        # Handle typing types
        if hasattr(python_type, "__origin__"):
            if python_type.__origin__ is list:
                item_type = python_type.__args__[0] if python_type.__args__ else String
                return List(cls.map_type(item_type))
            elif python_type.__origin__ is typing.Union:
                # Handle Optional types
                if type(None) in python_type.__args__:
                    non_none_types = [
                        t for t in python_type.__args__ if t is not type(None)
                    ]

                    if non_none_types:
                        return cls.map_type(non_none_types[0])
                return String  # Default to String for complex unions

        # Handle basic types
        return cls.TYPE_MAPPING.get(python_type, String)


class GraphQLTypeGenerator:
    """Generate GraphQL types from PynamoDB models"""

    def __init__(self):
        self.generated_types = {}

    def generate_type_from_model(self, model_class, type_name=None):
        """Generate GraphQL type from PynamoDB model"""

        if type_name is None:
            type_name = model_class.__name__

        # Prevent duplicate generation
        if type_name in self.generated_types:
            return self.generated_types[type_name]

        # Create attributes dict for the GraphQL type
        attrs = {}

        # Get model attributes
        for attr_name in dir(model_class):
            if not attr_name.startswith("_") and attr_name not in ["tables", "Meta"]:
                attr = getattr(model_class, attr_name)

                # Skip methods and class attributes
                if callable(attr) or hasattr(attr, "contribute_to_class"):
                    continue

                # Get the type of the attribute
                try:
                    if hasattr(attr, "attr_name"):
                        # This is a PynamoDB attribute
                        attr_type = self._get_attribute_type(attr)
                    else:
                        # Regular attribute, try to get type hints
                        attr_type = self._get_type_from_hints(model_class, attr_name)

                    if attr_type:
                        graphql_type = DataTypeMapper.map_type(attr_type)
                        attrs[attr_name] = Field(graphql_type)

                except Exception as e:
                    print(f"Warning: Could not process attribute {attr_name}: {e}")
                    # Default to String
                    attrs[attr_name] = Field(String)

        # Create the GraphQL type
        attrs["__module__"] = model_class.__module__

        # Create Meta class for the type
        class Meta:
            pass

        # Dynamically create the GraphQL type
        graph_type = type(type_name, (ObjectType,), {**attrs, "Meta": Meta})

        self.generated_types[type_name] = graph_type
        return graph_type

    def _get_attribute_type(self, attr):
        """Extract type from PynamoDB attribute"""
        # Check if it's a UnicodeAttribute, NumberAttribute, etc.
        attr_type_name = type(attr).__name__

        if "Unicode" in attr_type_name:
            return str
        elif "Number" in attr_type_name:
            return int
        elif "Boolean" in attr_type_name:
            return bool
        elif "Decimal" in attr_type_name:
            return Decimal
        elif "DateTime" in attr_type_name:
            return datetime
        elif "Binary" in attr_type_name:
            return bytes
        elif "List" in attr_type_name:
            return list
        elif "Map" in attr_type_name:
            return dict
        else:
            return str  # Default fallback

    def _get_type_from_hints(self, model_class, attr_name):
        """Get type from type hints"""
        try:
            hints = get_type_hints(model_class)
            return hints.get(attr_name, str)
        except Exception:
            return str

    def generate_enum_from_choices(self, choices_class, enum_name):
        """Generate GraphQL Enum from Django choices"""
        choices = getattr(choices_class, "CHOICES", [])

        if not choices:
            return None

        # Create enum values
        enum_values = {}
        for value, label in choices:
            # Convert to valid GraphQL enum name
            enum_key = label.upper().replace(" ", "_").replace("-", "_")
            enum_values[enum_key] = value

        return GraphQLEnum(enum_name, enum_values)

    def generate_all_types(self, models_module):
        """Generate GraphQL types for all models in a module"""
        import importlib

        if isinstance(models_module, str):
            models_module = importlib.import_module(models_module)

        generated_types = {}

        for name in dir(models_module):
            obj = getattr(models_module, name)

            # Check if it's a PynamoDB model class
            if (
                inspect.isclass(obj)
                and hasattr(obj, "Meta")
                and hasattr(obj.Meta, "table_name")
            ):
                graphql_type = self.generate_type_from_model(obj)
                generated_types[name] = graphql_type

        return generated_types
