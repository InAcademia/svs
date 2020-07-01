def get_matching_affiliation(scope, affiliation):
    for affiliation_mode in AFFILIATIONS:
        if affiliation_mode in scope:
            return AFFILIATIONS[affiliation_mode](affiliation)


def _is_student(affiliation):
    return _first_matching_value(['student'], affiliation)


def _is_employee(affiliation):
    return _first_matching_value(['employee'], affiliation)


def _is_member(affiliation):
    return (_first_matching_value(['member'], affiliation) or
            _is_student(affiliation) or
            _is_employee(affiliation) or
            _is_faculty_or_staff(affiliation))


def _is_alumni(affiliation):
    return _first_matching_value(['alum'], affiliation)


def _is_faculty_or_staff(affiliation):
    return _first_matching_value(['faculty', 'staff'], affiliation)


def _is_affiliated(affiliation):
    return (_is_student(affiliation) or
            _is_employee(affiliation) or
            _is_member(affiliation))


def _first_matching_value(accepted_values, bag):
    for v in accepted_values:
        if v in bag:
            return v

    return None

AFFILIATIONS = {
    'student': _is_student,
    'employee': _is_employee,
    'faculty+staff': _is_faculty_or_staff,
    'alum': _is_alumni,
    'member': _is_member
}
