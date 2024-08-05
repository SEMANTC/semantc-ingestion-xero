# coding: utf-8

"""
    Xero Payroll NZ

    This is the Xero Payroll API for orgs in the NZ region.  # noqa: E501

    Contact: api@xero.com
    Generated by: https://openapi-generator.tech
"""


import re  # noqa: F401

from xero_python.models import BaseModel


class EmployeeWorkingPattern(BaseModel):
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
    openapi_types = {"payee_working_pattern_id": "str", "effective_from": "date"}

    attribute_map = {
        "payee_working_pattern_id": "payeeWorkingPatternID",
        "effective_from": "effectiveFrom",
    }

    def __init__(
        self, payee_working_pattern_id=None, effective_from=None
    ):  # noqa: E501
        """EmployeeWorkingPattern - a model defined in OpenAPI"""  # noqa: E501

        self._payee_working_pattern_id = None
        self._effective_from = None
        self.discriminator = None

        self.payee_working_pattern_id = payee_working_pattern_id
        self.effective_from = effective_from

    @property
    def payee_working_pattern_id(self):
        """Gets the payee_working_pattern_id of this EmployeeWorkingPattern.  # noqa: E501

        The Xero identifier for for Employee working pattern  # noqa: E501

        :return: The payee_working_pattern_id of this EmployeeWorkingPattern.  # noqa: E501
        :rtype: str
        """
        return self._payee_working_pattern_id

    @payee_working_pattern_id.setter
    def payee_working_pattern_id(self, payee_working_pattern_id):
        """Sets the payee_working_pattern_id of this EmployeeWorkingPattern.

        The Xero identifier for for Employee working pattern  # noqa: E501

        :param payee_working_pattern_id: The payee_working_pattern_id of this EmployeeWorkingPattern.  # noqa: E501
        :type: str
        """
        if payee_working_pattern_id is None:
            raise ValueError(
                "Invalid value for `payee_working_pattern_id`, must not be `None`"
            )  # noqa: E501

        self._payee_working_pattern_id = payee_working_pattern_id

    @property
    def effective_from(self):
        """Gets the effective_from of this EmployeeWorkingPattern.  # noqa: E501

        The effective date of the corresponding salary and wages  # noqa: E501

        :return: The effective_from of this EmployeeWorkingPattern.  # noqa: E501
        :rtype: date
        """
        return self._effective_from

    @effective_from.setter
    def effective_from(self, effective_from):
        """Sets the effective_from of this EmployeeWorkingPattern.

        The effective date of the corresponding salary and wages  # noqa: E501

        :param effective_from: The effective_from of this EmployeeWorkingPattern.  # noqa: E501
        :type: date
        """
        if effective_from is None:
            raise ValueError(
                "Invalid value for `effective_from`, must not be `None`"
            )  # noqa: E501

        self._effective_from = effective_from