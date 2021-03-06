# ⁻*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015 Valentin Samir
from django.conf import settings
from django.core.cache import caches
from django.http import Http404

import os
import shutil
import json
import hashlib
from chardet.universaldetector import UniversalDetector

from pyprocmail import procmail

import exceptions
import forms_initial
import config

unicodeSpacesSet = set(procmail.parser.unicodeSpaces)


def get_parent_id(id):
    if not id:
        return id
    else:
        return ".".join(id.split('.')[:-1])


def get_current_index(id):
    return int(id.split('.')[-1])


def wizard_switch_by_stmt(stmt, alt=None):
    def f(wizard):
        return (
            wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == stmt and
            (alt is None or alt(wizard))
        )
    return f


def wizard_switch_by_kinds(kinds):
    def f(wizard):
        return (
            wizard.get_cleaned_data_for_step("simple_condition_kind") and
            wizard.get_cleaned_data_for_step("simple_condition_kind").get("kind") in kinds
        )
    return f


def escape_re(string):
    for char in '\\' + config.REGEX_CHARS:
        string = string.replace(char, '\\%s' % char)
    return string


def unescape_re(string):
    for char in config.REGEX_CHARS + '\\':
        string = string.replace('\\%s' % char, char)
    return string


def is_regex(string):
    for char in config.REGEX_CHARS:
        i = -1
        try:
            while True:
                i = string.index(char, i+1)
                if i == 0 or string[i-1] != '\\':
                    return True
        except ValueError:
            pass
    special_constructs = ['\\/', '\\<', '\\>']
    for const in special_constructs:
        if const in string:
            return True
    return False


def detect_charset(path):
    detector = UniversalDetector()
    with open(path) as f:
        i = 0
        for line in iter(f.readline, ""):
            detector.feed(line)
            # process at most the first 1000 lines
            if detector.done or i > 1000:
                break
            i += 1
    detector.close()
    result = detector.result
    if result['encoding'] in [None, "windows-1252"] or result['encoding'].startswith('ISO-8859'):
        return settings.PROCMAIL_FALLBACK_ENCODING
    else:
        return result['encoding']


def context(request, cntxt):
    base = {
        'PROCMAIL_INPLACE': settings.PROCMAIL_INPLACE,
        'PROCMAIL_DEBUG_DIR': settings.PROCMAIL_DEBUG_DIR,
        'PROCMAIL_OR_SCORE': settings.PROCMAIL_OR_SCORE,
        'PROCMAIL_VENDOR_CSS': settings.PROCMAIL_VENDOR_CSS,
        'PRCOMAIL_VENDOR_JAVASCRIPT': settings.PRCOMAIL_VENDOR_JAVASCRIPT,
        'current_namespace': request.resolver_match.namespace,
        'current_url_name': request.resolver_match.url_name,
        'current_view_name': "%s:%s" % (
            request.resolver_match.namespace,
            request.resolver_match.url_name
        ),
    }
    base.update(cntxt)
    return base


class ListControl(object):
    def __init__(self, string, data=None):
        self.string = string
        if data is None:
            self.data = {}
        else:
            self.data = data

    def __eq__(self, y):
        return self.string == y


def _process_procmailrc(rules, flat=None, in_simple=False):
    if flat is None:
        flat = []
    for r in rules:
        if r.is_comment():
            display = False
        else:
            display = True
        flat.append(
            ListControl(
                "in_item",
                data={
                    "in_simple": in_simple,
                    "id": r.id,
                    "parent_id": r.parent.id,
                    'display': display,
                }
            )
        )
        flat.append(r)
        if r.is_recipe() or r.is_assignment():
            try:
                initials, custom = forms_initial.simple_recipe(r)
                r.django = {
                    'is_simple': True,
                    'initials': initials,
                    'custom': custom,
                    'in_simple': in_simple,
                    'display': display,
                }
            except exceptions.NonSimple:
                r.django = {'is_simple': False, 'in_simple': in_simple, 'display': display}
            if r.is_recipe() and r.action.is_nested():
                flat.append(
                    ListControl(
                        "in_list",
                        data={
                            "in_simple": in_simple or r.django['is_simple'],
                            "id": r.id,
                            "parent_id": r.parent.id,
                            'display': display,
                        }
                    )
                )
                _process_procmailrc(r.action, flat, in_simple or r.django['is_simple'])
                flat.append(
                    ListControl("out_list", data={"in_simple": in_simple or r.django['is_simple']})
                )
        else:
            r.django = {'is_simple': False, 'in_simple': in_simple, 'display': display}
        flat.append(ListControl("out_item", data={"in_simple": in_simple}))
    return flat


def process_procmailrc(procmailrc, key):
    procmailrc.django = {'is_simple': False, 'in_simple': False}
    flat = _process_procmailrc(procmailrc)
    procmailrc.django['flat'] = flat
    procmailrc.django['key'] = key


def procmailrc_key(username, path):
    key = "%s-%s-%s" % (
        username,
        os.path.getmtime(path),
        os.path.getsize(path)
    )
    return hashlib.sha1(key.encode("utf-8", errors='replace')).hexdigest()


def get_procmailrc(user):
    procmailrc_path = get_procmailrc_path(user)
    key = procmailrc_key(user.username, procmailrc_path)
    procmailrc = caches['default'].get(key)
    if procmailrc is not None:
        return procmailrc
    # Try first using default encoding (utf-8 by default)
    try:
        procmailrc = procmail.parse(procmailrc_path, charset=settings.PROCMAIL_DEFAULT_ENCODING)
    except UnicodeDecodeError:
        # If an error occure, try detecting the encoding
        charset = detect_charset(procmailrc_path)
        procmailrc = procmail.parse(procmailrc_path, charset=charset)
    process_procmailrc(procmailrc, key)
    caches['default'].set(key, procmailrc, 3600)
    return procmailrc


def get_procmailrc_path(user):
    if settings.PROCMAIL_INPLACE:
        if settings.PROCMAIL_TEST_PROCMAILRC is not None:
            return settings.PROCMAIL_TEST_PROCMAILRC
        else:
            home = os.path.expanduser("~%s" % user.username)
            procmailrc_path = os.path.join(home, ".procmailrc")
    else:
        procmailrc_path = os.path.join(settings.PROCMAIL_DEBUG_DIR, "%s.procmailrc" % user.username)
        if not os.path.isfile(procmailrc_path):
            if settings.PROCMAIL_TEST_PROCMAILRC is not None:
                shutil.copy(settings.PROCMAIL_TEST_PROCMAILRC, procmailrc_path)
            else:
                home = os.path.expanduser("~%s" % user.username)
                if os.path.isfile(os.path.join(home, ".procmailrc")):
                    shutil.copy(os.path.join(home, ".procmailrc"), procmailrc_path)
    if not os.path.isfile(procmailrc_path) or os.path.getsize(procmailrc_path) < 2:
        with open(procmailrc_path, 'w') as f:
            f.write(settings.PROCMAIL_DEFAULT_PROCMAILRC)
    return procmailrc_path


def set_procmailrc(user, procmailrc):
    procmailrc_path = get_procmailrc_path(user)
    procmailrc = procmailrc.write(procmailrc_path, charset=settings.PROCMAIL_DEFAULT_ENCODING)
    key = procmailrc_key(user.username, procmailrc_path)
    process_procmailrc(procmailrc, key)
    caches['default'].set(key, procmailrc, 3600)


def oring(conditions):
    conds = []
    if len(conditions) <= 1:
        return conditions
    else:
        for cond in conditions:
            conds.append(procmail.ConditionScore(settings.PROCMAIL_OR_SCORE, 0, cond))
        return conds


def unoring(conditions):
    conds = []
    if len(conditions) <= 1:
        return conditions
    else:
        for cond in conditions:
            if (
                cond.is_score() and
                int(cond.x) == settings.PROCMAIL_OR_SCORE and
                int(cond.y) == 0 and
                is_simple_condition(cond.condition)
            ):
                conds.append(cond.condition)
            else:
                raise exceptions.NonOred("%s not or condition" % cond.render())
        return conds


def is_simple_condition(cond):
    if cond.is_size():
        return True
    elif cond.is_regex():
        return True
    elif cond.is_variable() and cond.condition.is_size():
        return True
    else:
        return


def is_simple_statement(stmt):
    if stmt.is_assignment():
        for name, value, quote in stmt.variables:
            if quote == '`':
                return False
        return True
    elif stmt.is_recipe():
        if stmt.conditions:
            return False
        elif stmt.action.is_save():
            return True
        elif stmt.action.is_forward():
            return len(stmt.action.recipients) == 1
        else:
            return False
    else:
        return False


def make_recipe(procmailrc, parent_id):
    r = procmail.Recipe(procmail.Header(), procmail.Action())
    try:
        r.parent = procmailrc[parent_id]
        r.parent.append(r)
        return r
    except KeyError:
        raise Http404()


def make_assignment(procmailrc, parent_id):
    r = procmail.Assignment()
    try:
        r.parent = procmailrc[parent_id]
        r.parent.append(r)
        return r
    except KeyError:
        raise Http404()


def update_recipe(recipe, title, comment, header, action, conditions):
    recipe.header = header
    recipe.action = action
    recipe.conditions = conditions
    recipe.meta_title = title
    recipe.meta_comment = comment


def update_assignment(assignement, title, comment, variables):
    assignement.meta_title = title
    assignement.meta_comment = comment
    assignement.variables = variables


def make_simple_rules(kind, title, comment, statements, conditions):
    if kind == "all":
        if len(statements) == 1 and statements[0].is_recipe():
            header = statements[0].header
            action = statements[0].action
            recipe = procmail.Recipe(header, action)
        elif len(statements) == 1 and statements[0].is_assignment():
            recipe = statements[0]
        else:
            action = procmail.ActionNested(statements)
            header = procmail.Header()
            recipe = procmail.Recipe(header, action)
        recipe.meta_custom = json.dumps({"kind": "all"})
        recipe.meta_title = title
        recipe.meta_comment = comment
        return recipe
    elif kind == "and":
        header = procmail.Header()
        if conditions:
            flags, condition = conditions[0]
            for letter in flags:
                setattr(header, letter, True)
        else:
            condition = []
        if len(statements) == 1 and statements[0].is_recipe():
            header = statements[0].header
            action = statements[0].action
        else:
            action = procmail.ActionNested(statements)
        recipe = procmail.Recipe(header, action, condition)
        prof = 0
        for flags, condition in conditions[1:]:
            header = procmail.Header()
            for letter in flags:
                setattr(header, letter, True)
            action = procmail.ActionNested([recipe])
            recipe = procmail.Recipe(header, action, condition)
            prof += 1
        recipe.meta_custom = json.dumps({"kind": "and"})
        recipe.meta_title = title
        recipe.meta_comment = comment
        return recipe
    elif kind == "or":
        stmt = []
        header = procmail.Header()
        if conditions:
            flags, condition = conditions[0]
            for letter in flags:
                setattr(header, letter, True)
        else:
            condition = []
        if len(statements) == 1 and statements[0].is_recipe():
            header = statements[0].header
            action = statements[0].action
        else:
            action = procmail.ActionNested(statements)
        recipe = procmail.Recipe(header, action, oring(condition))
        stmt.append(recipe)
        for flags, condition in conditions[1:]:
            header = procmail.Header()
            for letter in flags:
                setattr(header, letter, True)
            header.E = True
            if len(statements) == 1 and statements[0].is_recipe():
                header = statements[0].header
                action = statements[0].action
            else:
                action = procmail.ActionNested(statements)
            recipe = procmail.Recipe(header, action, oring(condition))
            stmt.append(recipe)
        if len(stmt) == 1:
            recipe = stmt[0]
        else:
            recipe = procmail.Recipe(procmail.Header(), procmail.ActionNested(stmt))
        recipe.meta_custom = json.dumps({"kind": "or"})
        recipe.meta_title = title
        recipe.meta_comment = comment
        return recipe
    else:
        raise ValueError("kind should be 'or' or 'and' or 'all'")
