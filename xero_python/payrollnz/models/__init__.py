# coding: utf-8

# flake8: noqa
"""
    Xero Payroll NZ

    This is the Xero Payroll API for orgs in the NZ region.  # noqa: E501

    OpenAPI spec version: 2.7.0
    Contact: api@xero.com
    Generated by: https://openapi-generator.tech
"""


# import models into model package
from xero_python.payrollnz.models.account import Account
from xero_python.payrollnz.models.accounts import Accounts
from xero_python.payrollnz.models.address import Address
from xero_python.payrollnz.models.bank_account import BankAccount
from xero_python.payrollnz.models.benefit import Benefit
from xero_python.payrollnz.models.calendar_type import CalendarType
from xero_python.payrollnz.models.deduction import Deduction
from xero_python.payrollnz.models.deduction_line import DeductionLine
from xero_python.payrollnz.models.deduction_object import DeductionObject
from xero_python.payrollnz.models.deductions import Deductions
from xero_python.payrollnz.models.earnings_line import EarningsLine
from xero_python.payrollnz.models.earnings_order import EarningsOrder
from xero_python.payrollnz.models.earnings_order_object import EarningsOrderObject
from xero_python.payrollnz.models.earnings_orders import EarningsOrders
from xero_python.payrollnz.models.earnings_rate import EarningsRate
from xero_python.payrollnz.models.earnings_rate_object import EarningsRateObject
from xero_python.payrollnz.models.earnings_rates import EarningsRates
from xero_python.payrollnz.models.earnings_template import EarningsTemplate
from xero_python.payrollnz.models.earnings_template_object import EarningsTemplateObject
from xero_python.payrollnz.models.employee import Employee
from xero_python.payrollnz.models.employee_earnings_templates import (
    EmployeeEarningsTemplates,
)
from xero_python.payrollnz.models.employee_leave import EmployeeLeave
from xero_python.payrollnz.models.employee_leave_balance import EmployeeLeaveBalance
from xero_python.payrollnz.models.employee_leave_balances import EmployeeLeaveBalances
from xero_python.payrollnz.models.employee_leave_object import EmployeeLeaveObject
from xero_python.payrollnz.models.employee_leave_setup import EmployeeLeaveSetup
from xero_python.payrollnz.models.employee_leave_setup_object import (
    EmployeeLeaveSetupObject,
)
from xero_python.payrollnz.models.employee_leave_type import EmployeeLeaveType
from xero_python.payrollnz.models.employee_leave_type_object import (
    EmployeeLeaveTypeObject,
)
from xero_python.payrollnz.models.employee_leave_types import EmployeeLeaveTypes
from xero_python.payrollnz.models.employee_leaves import EmployeeLeaves
from xero_python.payrollnz.models.employee_object import EmployeeObject
from xero_python.payrollnz.models.employee_opening_balance import EmployeeOpeningBalance
from xero_python.payrollnz.models.employee_opening_balances_object import (
    EmployeeOpeningBalancesObject,
)
from xero_python.payrollnz.models.employee_pay_template import EmployeePayTemplate
from xero_python.payrollnz.models.employee_pay_template_object import (
    EmployeePayTemplateObject,
)
from xero_python.payrollnz.models.employee_pay_templates import EmployeePayTemplates
from xero_python.payrollnz.models.employee_statutory_leave_balance import (
    EmployeeStatutoryLeaveBalance,
)
from xero_python.payrollnz.models.employee_statutory_leave_balance_object import (
    EmployeeStatutoryLeaveBalanceObject,
)
from xero_python.payrollnz.models.employee_statutory_leave_summary import (
    EmployeeStatutoryLeaveSummary,
)
from xero_python.payrollnz.models.employee_statutory_leaves_summaries import (
    EmployeeStatutoryLeavesSummaries,
)
from xero_python.payrollnz.models.employee_statutory_sick_leave import (
    EmployeeStatutorySickLeave,
)
from xero_python.payrollnz.models.employee_statutory_sick_leave_object import (
    EmployeeStatutorySickLeaveObject,
)
from xero_python.payrollnz.models.employee_statutory_sick_leaves import (
    EmployeeStatutorySickLeaves,
)
from xero_python.payrollnz.models.employee_tax import EmployeeTax
from xero_python.payrollnz.models.employee_tax_object import EmployeeTaxObject
from xero_python.payrollnz.models.employees import Employees
from xero_python.payrollnz.models.employment import Employment
from xero_python.payrollnz.models.employment_object import EmploymentObject
from xero_python.payrollnz.models.gross_earnings_history import GrossEarningsHistory
from xero_python.payrollnz.models.invalid_field import InvalidField
from xero_python.payrollnz.models.leave_accrual_line import LeaveAccrualLine
from xero_python.payrollnz.models.leave_earnings_line import LeaveEarningsLine
from xero_python.payrollnz.models.leave_period import LeavePeriod
from xero_python.payrollnz.models.leave_periods import LeavePeriods
from xero_python.payrollnz.models.leave_type import LeaveType
from xero_python.payrollnz.models.leave_type_object import LeaveTypeObject
from xero_python.payrollnz.models.leave_types import LeaveTypes
from xero_python.payrollnz.models.pagination import Pagination
from xero_python.payrollnz.models.pay_run import PayRun
from xero_python.payrollnz.models.pay_run_calendar import PayRunCalendar
from xero_python.payrollnz.models.pay_run_calendar_object import PayRunCalendarObject
from xero_python.payrollnz.models.pay_run_calendars import PayRunCalendars
from xero_python.payrollnz.models.pay_run_object import PayRunObject
from xero_python.payrollnz.models.pay_runs import PayRuns
from xero_python.payrollnz.models.pay_slip import PaySlip
from xero_python.payrollnz.models.pay_slip_object import PaySlipObject
from xero_python.payrollnz.models.pay_slips import PaySlips
from xero_python.payrollnz.models.payment_line import PaymentLine
from xero_python.payrollnz.models.payment_method import PaymentMethod
from xero_python.payrollnz.models.payment_method_object import PaymentMethodObject
from xero_python.payrollnz.models.problem import Problem
from xero_python.payrollnz.models.reimbursement import Reimbursement
from xero_python.payrollnz.models.reimbursement_line import ReimbursementLine
from xero_python.payrollnz.models.reimbursement_object import ReimbursementObject
from xero_python.payrollnz.models.reimbursements import Reimbursements
from xero_python.payrollnz.models.salary_and_wage import SalaryAndWage
from xero_python.payrollnz.models.salary_and_wage_object import SalaryAndWageObject
from xero_python.payrollnz.models.salary_and_wages import SalaryAndWages
from xero_python.payrollnz.models.settings import Settings
from xero_python.payrollnz.models.statutory_deduction import StatutoryDeduction
from xero_python.payrollnz.models.statutory_deduction_category import (
    StatutoryDeductionCategory,
)
from xero_python.payrollnz.models.statutory_deduction_line import StatutoryDeductionLine
from xero_python.payrollnz.models.statutory_deduction_object import (
    StatutoryDeductionObject,
)
from xero_python.payrollnz.models.statutory_deductions import StatutoryDeductions
from xero_python.payrollnz.models.superannuation_line import SuperannuationLine
from xero_python.payrollnz.models.superannuation_object import SuperannuationObject
from xero_python.payrollnz.models.superannuations import Superannuations
from xero_python.payrollnz.models.tax_code import TaxCode
from xero_python.payrollnz.models.tax_line import TaxLine
from xero_python.payrollnz.models.tax_settings import TaxSettings
from xero_python.payrollnz.models.timesheet import Timesheet
from xero_python.payrollnz.models.timesheet_earnings_line import TimesheetEarningsLine
from xero_python.payrollnz.models.timesheet_line import TimesheetLine
from xero_python.payrollnz.models.timesheet_line_object import TimesheetLineObject
from xero_python.payrollnz.models.timesheet_object import TimesheetObject
from xero_python.payrollnz.models.timesheets import Timesheets
from xero_python.payrollnz.models.tracking_categories import TrackingCategories
from xero_python.payrollnz.models.tracking_category import TrackingCategory