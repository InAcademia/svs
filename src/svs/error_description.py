from enum import Enum

ERROR_DESC = "error_description"
LOG_MSG = "logging"


class ErrorDescription(dict, Enum):
    """
    This enum provides a common place for all error_description and their corresponding logging statements for all
    error scenarios.

    error_description can be accessed for example as following:
    ErrorDescription.NO_AFFILIATION_ATTR[ERROR_DESC]

    logging can be accessed for example as following:
    ErrorDescription.NO_AFFILIATION_ATTR[LOG_MSG]
    """

    NO_AFFILIATION_ATTR = {ERROR_DESC: "no affiliation available for this user",
                           LOG_MSG: "No affiliation attribute from IDP"}

