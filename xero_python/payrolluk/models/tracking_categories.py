# coding: utf-8

"""
    Xero Payroll UK

    This is the Xero Payroll API for orgs in the UK region.  # noqa: E501

    OpenAPI spec version: 2.2.14
    Contact: api@xero.com
    Generated by: https://openapi-generator.tech
"""


import re  # noqa: F401

from xero_python.models import BaseModel


class TrackingCategories(BaseModel):
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
    openapi_types = {
        "pagination": "Pagination",
        "problem": "Problem",
        "tracking_categories": "TrackingCategory",
    }

    attribute_map = {
        "pagination": "pagination",
        "problem": "problem",
        "tracking_categories": "trackingCategories",
    }

    def __init__(
        self, pagination=None, problem=None, tracking_categories=None
    ):  # noqa: E501
        """TrackingCategories - a model defined in OpenAPI"""  # noqa: E501

        self._pagination = None
        self._problem = None
        self._tracking_categories = None
        self.discriminator = None

        if pagination is not None:
            self.pagination = pagination
        if problem is not None:
            self.problem = problem
        if tracking_categories is not None:
            self.tracking_categories = tracking_categories

    @property
    def pagination(self):
        """Gets the pagination of this TrackingCategories.  # noqa: E501


        :return: The pagination of this TrackingCategories.  # noqa: E501
        :rtype: Pagination
        """
        return self._pagination

    @pagination.setter
    def pagination(self, pagination):
        """Sets the pagination of this TrackingCategories.


        :param pagination: The pagination of this TrackingCategories.  # noqa: E501
        :type: Pagination
        """

        self._pagination = pagination

    @property
    def problem(self):
        """Gets the problem of this TrackingCategories.  # noqa: E501


        :return: The problem of this TrackingCategories.  # noqa: E501
        :rtype: Problem
        """
        return self._problem

    @problem.setter
    def problem(self, problem):
        """Sets the problem of this TrackingCategories.


        :param problem: The problem of this TrackingCategories.  # noqa: E501
        :type: Problem
        """

        self._problem = problem

    @property
    def tracking_categories(self):
        """Gets the tracking_categories of this TrackingCategories.  # noqa: E501


        :return: The tracking_categories of this TrackingCategories.  # noqa: E501
        :rtype: TrackingCategory
        """
        return self._tracking_categories

    @tracking_categories.setter
    def tracking_categories(self, tracking_categories):
        """Sets the tracking_categories of this TrackingCategories.


        :param tracking_categories: The tracking_categories of this TrackingCategories.  # noqa: E501
        :type: TrackingCategory
        """

        self._tracking_categories = tracking_categories