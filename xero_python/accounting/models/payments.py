# coding: utf-8

"""
    Accounting API

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)  # noqa: E501

    OpenAPI spec version: 2.2.2
    Contact: api@xero.com
    Generated by: https://openapi-generator.tech
"""


import re  # noqa: F401

from xero_python.models import BaseModel


class Payments(BaseModel):
    """NOTE: This class is auto generated by OpenAPI Generator.
    Ref: https://openapi-generator.tech

    Do not edit the class manually.
    """

    """
    Attributes:
      openapi_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    openapi_types = {"payments": "list[Payment]"}

    attribute_map = {"payments": "Payments"}

    def __init__(self, payments=None):  # noqa: E501
        """Payments - a model defined in OpenAPI"""  # noqa: E501

        self._payments = None
        self.discriminator = None

        if payments is not None:
            self.payments = payments

    @property
    def payments(self):
        """Gets the payments of this Payments.  # noqa: E501


        :return: The payments of this Payments.  # noqa: E501
        :rtype: list[Payment]
        """
        return self._payments

    @payments.setter
    def payments(self, payments):
        """Sets the payments of this Payments.


        :param payments: The payments of this Payments.  # noqa: E501
        :type: list[Payment]
        """

        self._payments = payments
