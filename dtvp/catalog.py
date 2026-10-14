"""Stable keyset cursors, bound to the active search and ordering."""

import base64
import json

from fastapi import HTTPException
from sqlalchemy import and_, or_

from dtvp.storage import canonical, digest


def page_cursor(value, record_id, scope):
    return base64.urlsafe_b64encode(
        canonical([value, record_id, digest(canonical(scope))])
    ).decode()


def after_cursor(query, column, id_column, cursor, scope, *, descending=False, value_parser=None):
    if not cursor:
        return query
    try:
        value, record_id, signature = json.loads(base64.urlsafe_b64decode(cursor))
        if (
            not isinstance(value, str)
            or not isinstance(record_id, str)
            or signature != digest(canonical(scope))
        ):
            raise ValueError()
    except ValueError, TypeError, UnicodeError:
        raise HTTPException(422, "Invalid cursor; restart this search") from None
    if value_parser:
        try:
            value = value_parser(value)
        except ValueError:
            raise HTTPException(422, "Invalid cursor; restart this search") from None
    if descending:
        return query.where(or_(column < value, and_(column == value, id_column < record_id)))
    return query.where(or_(column > value, and_(column == value, id_column > record_id)))
