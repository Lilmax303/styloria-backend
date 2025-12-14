# core/password_validators.py

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class ComplexityValidator:
    """
    Password must be:
    - 10 to 50 characters
    - contain at least one lowercase letter
    - contain at least one uppercase letter
    - contain at least one digit
    - contain at least one special character
    """

    def validate(self, password, user=None):
        errors = []

        if len(password) < 10 or len(password) > 50:
            errors.append(
                _("Password must be between 10 and 50 characters long.")
            )

        if not re.search(r'[a-z]', password):
            errors.append(_("Password must contain at least one lowercase letter."))

        if not re.search(r'[A-Z]', password):
            errors.append(_("Password must contain at least one uppercase letter."))

        if not re.search(r'\d', password):
            errors.append(_("Password must contain at least one digit."))

        if not re.search(r'[^A-Za-z0-9]', password):
            errors.append(_("Password must contain at least one special character."))

        if errors:
            raise ValidationError(errors)

    def get_help_text(self):
        return _(
            "Your password must be 10–50 characters long and contain at "
            "least one uppercase letter, one lowercase letter, one number, "
            "and one special character."
        )