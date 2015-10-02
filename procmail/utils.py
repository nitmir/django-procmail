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

import os
import shutil
import json

from pyprocmail import procmail

import exceptions
import forms_initial


unicodeSpacesSet = set(procmail.parser.unicodeSpaces)


def set_extra(self, **kwargs):
    self.extra = kwargs
    return self


def set_simple(rules):
    for r in rules:
        if r.is_recipe() or r.is_assignment():
            try:
                initials, custom = forms_initial.simple_recipe(r)
                r.django = {
                    'is_simple': True,
                    'initials': initials,
                    'custom': custom,
                }
            except exceptions.NonSimple:
                r.django = {'is_simple': False}
            if r.is_recipe() and r.action.is_nested():
                set_simple(r.action)
        else:
            r.django = {'is_simple': False}


def get_procmailrc(user):
    procmailrc_path = get_procmailrc_path(user)
    procmailrc = procmail.parse(procmailrc_path)
    set_simple(procmailrc)
    return procmailrc


def get_procmailrc_path(user):
    if settings.PROCMAIL_INPLACE:
        home = os.path.expanduser("~%s" % user.username)
        procmailrc_path = os.path.join(home, ".procmailrc")
    else:
        procmailrc_path = os.path.join(settings.PROCMAIL_DEBUG_DIR, "%s.procmailrc" % user.username)
        if not os.path.isfile(procmailrc_path):
            home = os.path.expanduser("~%s" % user.username)
            if os.path.isfile(os.path.join(home, ".procmailrc")):
                shutil.copy(os.path.join(home, ".procmailrc"), procmailrc_path)
    if not os.path.isfile(procmailrc_path):
        open(procmailrc_path, 'a').close()
    return procmailrc_path


def set_procmailrc(user, procmailrc):
    procmailrc_path = get_procmailrc_path(user)
    procmailrc.write(procmailrc_path)


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
                cond.is_score()
                and int(cond.x) == settings.PROCMAIL_OR_SCORE
                and int(cond.y) == 0
                and is_simple_condition(cond.condition)
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


class HidableFieldsForm(object):
    def show_init(self):
        for field_name, field in self.fields.items():
            if self.data and self.add_prefix(field_name) in self.data:
                value = field.to_python(self.data[self.add_prefix(field_name)])
            elif self.initial:
                value = self.initial.get(field_name, field.initial)
            else:
                value = field.initial
            if field.extra.get('show_if_value_not', '__RESERVED_VALUE_TYHU') == value \
                    and not self.errors.get(field_name):
                field.show = False
            else:
                field.show = True
        return ""


def show(self, field_name):
    try:
        if field_name in self._show_dict:
            return self._show_dict[field_name]
    except AttributeError:
        self._show_dict = {}

    i = 0
    for form in self:
        if self.data and form.add_prefix(field_name) in self.data:
            ini = form.fields[field_name].to_python(self.data[form.add_prefix(field_name)])
        elif form.data and form.add_prefix(field_name) in form.data:
            ini = form.fields[field_name].to_python(form.data[form.add_prefix(field_name)])
        elif self.initial and len(self.initial) > i:
            ini = self.initial[i].get(field_name, form.fields[field_name].initial)
        else:
            ini = form.fields[field_name].initial
        if form.fields[field_name].extra.get('show_if_value_not', '__RESERVED_VALUE_TYHU') == ini \
                and not form.errors.get(field_name):
            self._show_dict[field_name] = False
        else:
            self._show_dict[field_name] = True
            break
        i += 1
    return self._show_dict[field_name]


def show_init(self):
    for form in self:
        for field_name, field in form.fields.items():
            field.show = show(self, field_name)
    return ""


def make_simple_rules(kind, title, comment, statements, conditions):
    if kind == "all":
        if len(statements) == 1 and statements[0].is_recipe():
            action = statements[0].action
            header = procmail.Header()
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
