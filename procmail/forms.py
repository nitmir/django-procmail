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
from django import forms
from django.forms.formsets import BaseFormSet, formset_factory
from django.conf import settings
from django.utils.translation import ugettext_lazy as _

import re
import json
import collections

from pyprocmail import procmail


def set_extra(self, **kwargs):
    self.extra = kwargs
    return self

unicodeSpacesSet = set(procmail.parser.unicodeSpaces)

forms.Field.set_extra = set_extra
forms.Field.extra = {}


def oring(conditions):
    conds = []
    if len(conditions) <= 1:
        return conditions
    else:
        for cond in conditions:
            conds.append(procmail.ConditionScore(settings.PROCMAIL_OR_SCORE, 0, cond))
        return conds


class NonOred(ValueError):
    pass


class NonSimple(ValueError):
    pass


def unoring(conditions):
    conds = []
    if len(conditions) <= 1:
        return conditions
    else:
        for cond in conditions:
            if cond.is_score() and int(cond.x) == settings.PROCMAIL_OR_SCORE and int(cond.y) == 0 and is_simple_condition(cond.condition):
                conds.append(cond.condition)
            else:
                raise NonOred("%s not or condition" % cond.render())
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


def initial_simple_recipe(r):
    if r.meta_custom:
        custom = json.loads(r.meta_custom)
    else:
        custom = {}
    kind = None
    actions = []
    conditions = []

    if not r.action.is_nested():
        if not r.action.is_save() and not r.action.is_forward():
            # not simple
            raise NonSimple()
        if len(r.conditions)<=1:
            if r.conditions and not is_simple_condition(r.conditions[0]):
                # not simple
                raise NonSimple()
            kind = custom.get('kind', "and")
            conditions.append((r.header.flag, r.conditions))
        else:
            kind = "or"
            try:
                conditions.append((r.header.flag, unoring(r.conditions)))
            except NonOred:
                if not all(is_simple_condition(c) for c in r.conditions):
                    # not simple
                    raise NonSimple()
                kind = "and"
                conditions.append((r.header.flag, r.conditions))
        actions.append((r.header.flag, r.action))
    else:
        if all(is_simple_statement(stmt) for stmt in r):
            if len(r.conditions)<=1:
                if r.conditions and not is_simple_condition(r.conditions[0]):
                    # not simple
                    raise NonSimple()
                kind = custom.get('kind', "and")
                conditions.append((r.header.flag, r.conditions))
            else:
                kind = "or"
                try:
                    conditions.append((r.header.flag, unoring(r.conditions)))
                except NonOred:
                    if not all(is_simple_condition(c) for c in r.conditions):
                        # not simple
                        raise NonSimple()
                    kind = "and"
                    conditions.append((r.header.flag, r.conditions))
            for stmt in r:
                if stmt.is_assignment():
                    actions.append((stmt.header.flag, stmt))
                else:
                    actions.append((stmt.header.flag, stmt.action))
        else:
            if len(r)>1:
                kind = "or"
                for stmt in r:
                    if stmt.is_recipe() and stmt.action.is_nested():
                        if not all(is_simple_statement(s) for s in stmt):
                            raise NonSimple()
                    elif not stmt.is_recipe() or (not stmt.action.is_save() and not stmt.action.is_forward()):
                        raise NonSimple()
                    try:
                        conditions.append((stmt.header.flag, unoring(stmt.conditions)))
                    except NonOred:
                        raise NonSimple()
                if not all(s.action == r[0].action for s in r):
                    raise NonSimple()
                if r[0].action.is_nested():
                    for stmt in r[0].action:
                        if stmt.is_assignment():
                            actions.append((stmt.header.flag, stmt))
                        else:
                            actions.append((stmt.header.flag, stmt.action))
                else:
                    actions.append((r[0].header.flag, r[0].action))
            else:
                # len(r) == 1
                kind = "and"
                rr = r
                while len(rr) == 1 and rr.is_recipe() and rr.action.is_nested():
                    if not all(is_simple_condition(c) for c in rr.conditions):
                        raise NonSimple()
                    conditions.append((rr.header.flag, rr.conditions))
                    rr = rr[0]
                conditions.append((rr.header.flag, rr.conditions))
                if not all(is_simple_statement(stmt) for stmt in rr):
                    raise NonSimple()
                for stmt in rr:
                    if stmt.is_assignment():
                        actions.append((stmt.header.flag, stmt))
                    else:
                        actions.append((stmt.header.flag, stmt.action))

    meta_initial = meta_form_initial(r)

    cond_kind_initial = {'kind': kind}

    conditions_initial = []
    for flag, conds in conditions:
        for cond in conds:
            conditions_initial.append(initial_simple_condition(flag, cond))

    actions_initial = []
    for flag, action in actions:
        actions_initial.append(initial_simple_action(flag, action))
    return {
        'meta': meta_initial,
        'condition_kind': cond_kind_initial,
        'conditions': conditions_initial,
        'actions': actions_initial
    }, custom


class MetaForm(forms.Form):
    title = forms.CharField(label=_('title'), max_length=100)
    comment = forms.CharField(label=_('comment'), max_length=256, required=False)


class SimpleConditionKind(forms.Form):
    kind = forms.ChoiceField(
        label='',
        widget=forms.RadioSelect,
        choices=[
            ("and", _("matching every rules below")),
            ("or", _("matching any rules below")),
            ("all", _("all mails")),
        ]
    )


def initial_simple_condition(flag, condition):
    if condition.is_negate():
        negate = True
        condition = condition.condition
    else:
        negate = False

    data = {}

    data['object'] = None
    if 'H' and 'B' in flag:
        data['object'] = "headers_body"
    elif 'B' in flag:
        data['object'] = "body"

    if condition.is_regex():
        prefix = "^\^([^:]+):\[ \]\*"
        contain = "\.\*(.+)\.\*$"
        equal = "(.+)\$$"
        exists = "\.\*$"
        regex = "(.+)$"

        r = re.match(prefix, condition.regex)
        if r is not None:
            contain = "^\^[^:]+:\[ \]\*" + contain
            equal = "^\^[^:]+:\[ \]\*" + equal
            exists = "^\^[^:]+:\[ \]\*" + exists
            regex = "^\^[^:]+:\[ \]\*" + regex
            prefix = r.group(1)
        else:
            contain = '^' + contain
            equal = '^' + equal
            exists = '^' + exists
            regex = '^' + regex
            prefix = None

        if data['object'] is None:
            if prefix == "Subject":
                data['object'] = "Subject"
            elif prefix == "From":
                data['object'] = "From"
            elif prefix == "To":
                data['object'] = "To"
            elif prefix is not None:
                data['object'] = "custom_header"
                data["custom_header"] = prefix
            else:
                data['object'] = "headers"

        param = None
        for match, exp in [('contain', contain), ('equal', equal), ('exists', exists), ('regex', regex)]:
            r = re.match(exp, condition.regex)
            if r is not None:
                try:
                    param = r.group(1)
                except IndexError:
                    param = ""
                break
        assert param is not None
        if match == 'equal':
            for i in range(0, len(param)):
                if not param[i] == '\\' and not param[i].isalnum():
                    if not i>0 or not param[i-1] == '\\':
                        match = "regex"
                        param = param + '$'
        if negate:
            data['match'] = "not_%s" % match
        else:
            data['match'] = match
        if match != "regex":
            data['param'] = re.sub('\\\(.)','\\1', param)
        else:
            data['param'] = param

        return data


class SimpleCondition(forms.Form):

    conditions = None

    object = forms.ChoiceField(
        label=_('object'),
        choices=[
            ("", ""),
            ("Subject", _("Subject")),
            ("From", _("From")),
            ("To", _("To")),
            ("custom_header", "..."),
            ("headers", _("headers")),
            ("body", _("body")),
            ("headers_body", _("headers and body")),
        ],
        required=False
    )

    custom_header = forms.CharField(label=_('custom header'), max_length=256, required=False)

    match = forms.ChoiceField(
        label=_('match'),
        choices=[
            ("", ""),
            ("contain", _("contain")),
            ("not_contain", _("does not contain")),
            ("equal", _("is equal to")),
            ("not_equal", _("is differant than")),
            ("exists", _("exists")),
            ("not_exists", _("does not exists")),
            ("regex", _("match the regular expression")),
            ("not_regex", _("do not match the regular expression")),
            ("size_g", _("size strictly greater than")),
            ("size_l", _("size strictly lower than")),
        ],
        required=False
    )

    param = forms.CharField(label=_('parameter'), max_length=256, required=False)

    def clean_custom_header(self):
        if ':' in self.cleaned_data["custom_header"]:
            raise forms.ValidationError("A header name cannot contain ':'")
        return self.cleaned_data["custom_header"].strip()

    def clean(self):
        data = self.cleaned_data
        if not data.get("match") or data.get('DELETE', False):
            return
        if data['object'] == "custom_header" and not data["custom_header"]:
            raise forms.ValidationError("Please specify a custom header")
        if data["match"] not in ["exists", "not_exists"] and not data["param"]:
            raise forms.ValidationError("Please specify a parameter")
        if data["match"] in ["size_g", "size_l"]:
            try:
                data["param"] = int(data["param"].strip())
            except ValueError:
                raise forms.validationError("Parameter must be a whole number of byte")
        if data["match"] in ["regex", "not_regex"]:
            try:
                re.compile(data["param"])
            except re.error as error:
                raise forms.validationError("Bad regular expression : %s" % error)

        flags = {}
        if data["object"] == "body":
            flags['B'] = True
        elif data["object"] == "headers_body":
            flags['H'] = True
            flags['B'] = True
        else:
            flags['H'] = True
        flags = flags.keys()
        flags.sort()
        self.flags = tuple(flags)

        if data["object"] == "Subject":
            prefix = "^Subject:[ ]*"
        elif data["object"] == "From":
            prefix = "^From:[ ]*"
        elif data["object"] == "To":
            prefix = "^To:[ ]*"
        elif data["object"] == "custom_header":
            prefix = "^%s:[ ]*" % re.escape(data["custom_header"])
        else:
            prefix = ""

        if data["match"] in [
            "contain", "not_contain", "equal", "not_equal",
            "exists", "not_exists", "regex", "not_regex"
        ]:
            if data["match"].startswith("not_"):
                negate = True
                match = data["match"][4:]
            else:
                negate = False
                match = data["match"]
            if data["match"] == "contain":
                regex = "%s.*%s.*" % (prefix, re.escape(data["param"]))
            elif match == "equal":
                regex = "%s%s$" % (prefix, re.escape(data["param"]))
            elif match == "exists":
                regex = "%s.*" % prefix 
            elif match == "regex":
                regex = "%s%s" % (prefix, data["param"])
            condition = procmail.ConditionRegex(regex)
            if negate:
               condition = procmail.ConditionNegate(condition)
            self.conditions = [condition]
        elif data["match"] in ["size_g", "size_l"]:
            if data["match"] == "size_g":
                sign = '>'
            else:
                sign = '<'
            if prefix:
                condition1 = procmail.ConditionRegex("%s[ ]*\/.*" % prefix)
                condition2 = procmail.ConditionVariable(
                    "MATCH",
                    procmail.ConditionSize(sign, data["param"])
                )
                self.conditions = [condition1, condition2]
            else:
                condition = procmail.ConditionSize(sign, data["param"])
                self.conditions = [condition]
        else:
            raise forms.ValidationError("Should not happening, contact an administrator 1")

class SimpleConditionBaseSet(BaseFormSet):
    def clean(self):
        conditions = collections.defaultdict(list)
        for form in self.forms:
            if form.errors:
                return
            if form.conditions is not None:
                conditions[form.flags].extend(form.conditions)
        self.conditions = conditions.items()

    def make_rules(self, kind, title, comment, statements):
        conditions = self.conditions
        if kind == "and":
            flags, condition = conditions[0]
            header = procmail.Header()
            for letter in flags:
                setattr(header, letter, True)
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
            recipe.meta_custom = json.dumps({"kind": "and", "prof":prof})
            recipe.meta_title = title
            recipe.meta_comment = comment
            return recipe
        elif kind == "or":
            stmt = []

            flags, condition = conditions[0]
            header = procmail.Header()
            for letter in flags:
                setattr(header, letter, True)
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
                header.A = True
                if len(statements) == 1 and statements[0].is_recipe():
                    action = statements[0].action
                else:
                    action = procmail.ActionNested(statements)
                recipe = procmail.Recipe(header, action, oring(condition))
                stmt.append(recipe)
            if len(stmt) == 1:
                recipe = stmt[0]
                multiflag = False
            else:
                recipe = procmail.Recipe(procmail.Header(), procmail.ActionNested(stmt))
                multiflag = True
            recipe.meta_custom = json.dumps({"kind": "or", 'multiflag': multiflag})
            recipe.meta_title = title
            recipe.meta_comment = comment
            return recipe
        else:
            raise ValueError("kind should be 'or' or 'and'")
                
SimpleConditionSet = formset_factory(
    SimpleCondition,
    extra=1,
    formset=SimpleConditionBaseSet,
    can_delete=True
)

def initial_simple_action(flag, action):
    data = {}
    if action.is_statement() and action.is_assignment():
        if len(action.variables)!=1:
            raise RuntimeError()
        data['action'] = "variable"
        data['variable_name'] = action.variables[0][0]
        data['variable_value'] = action.variables[0][1] or ""
    elif action.is_action():
        if action.is_save():
            if action.path == "/dev/null":
                data['action'] = "delete"
            else:
                if 'c' in flag:
                    data['action'] = "copy"
                else:
                    data['action'] = "save"
                data['param'] = action.path
        elif action.is_forward():
            if len(action.recipients) != 1:
                raise RuntimeError()
            data['param'] = action.recipients[0]
            if 'c' in flag:
                data['action'] = "redirect_copy"
            else:
                data['action'] = "redirect"
        else:
            raise ValueError(action)
    else:
        raise ValueError(action)
    return data


class SimpleAction(forms.Form):
    statement = None

    action = forms.ChoiceField(
        label=_('action'),
        choices=[
            ("", ""),
            ("save", _("Save mail in")),
            ("copy", _("Copy mail in")),
            ("redirect", _("Redirect mail to")),
            ("redirect_copy", _("Send a copy to")),
            ("delete", _("Delete mail")),
            ("variable", _("Define a variable")),
        ]
    )

    param = forms.CharField(label=_('parameter'), max_length=256, required=False)
    variable_name = forms.CharField(label=_('variable name'), max_length=256, required=False)
    variable_value = forms.CharField(label=_('variable value'), max_length=256, required=False)

    def clean(self):
        data = self.cleaned_data
        if not data['action'] or data.get('DELETE', False):
            return
        if data['action'] in ["save", "copy", "redirect", "redirect_copy"] and not data['param']:
            raise forms.ValidationError("Please specify a %s" % self.param.label)
        if data['action'] == "variable" and not data["variable_name"]:
            raise forms.ValidationError("Please specify a %s" % self.variable_name.label)

        if data['action'] == "save":
            header = procmail.Header(lockfile=True)
            action = procmail.ActionSave(data['param'])
            self.statement = procmail.Recipe(header, action)
        elif data['action'] == "copy":
            header = procmail.Header(lockfile=True)
            header.c = True
            action = procmail.ActionSave(data['param'])
            self.statement = procmail.Recipe(header, action)
        elif data['action'] == "redirect":
            header = procmail.Header()
            action = procmail.ActionForward([data['param']])
            self.statement = procmail.Recipe(header, action)
        elif data['action'] == "redirect_copy":
            header = procmail.Header()
            header.c = 1
            action = procmail.ActionForward([data['param']])
            self.statement = procmail.Recipe(header, action)
        elif data['action'] == "delete":
            header = procmail.Header()
            action = procmail.ActionSave("/dev/null")
            self.statement = procmail.Recipe(header, action)
        elif data['action'] == "variable":
            self.statement = procmail.Assignment(
                [(data["variable_name"], data["variable_value"], '"')]
            )
        else:
            raise forms.ValidationError("Should not happening, contact an administrator 2")


class SimpleActionBaseSet(BaseFormSet):
    def clean(self):
        statements = []
        for form in self.forms:
            if form.errors:
                return
            if form.statement is not None:
                statements.append(form.statement)
        self.statements = statements


SimpleActionSet = formset_factory(
    SimpleAction,
    extra=1,
    formset=SimpleActionBaseSet,
    can_delete=True
)


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


class AssignmentBaseFormSet(BaseFormSet):
    def clean(self):
        variables = []
        for form in self.forms:
            if 'variable_name' in form.cleaned_data and not form.cleaned_data.get('DELETE', False):
                variables.append(
                    (
                        form.cleaned_data['variable_name'],
                        form.cleaned_data.get('value', None),
                        form.cleaned_data.get('quote', None)
                    )
                )
        if not variables:
            raise forms.ValidationError(
                "You need at least one assignement on a assignement satement"
            )
        self.variables = variables


class HeaderForm(forms.Form, HidableFieldsForm):

    H = forms.BooleanField(
        label=_("Flag H"),
        help_text=_("Condition lines examine the headers of the message."),
        required=False,
        initial=True
    ).set_extra(show_if_value_not=True)
    B = forms.BooleanField(
        label=_("Flag B"),
        help_text=_("Condition lines examine the body of the message."),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    h = forms.BooleanField(
        label=_("Flag h"),
        help_text=_("Action line gets fed the headers of the message."),
        required=False,
        initial=True
    ).set_extra(show_if_value_not=True)
    b = forms.BooleanField(
        label=_("Flag b"),
        help_text=_("Action line gets fed the body of the message."),
        required=False,
        initial=True
    ).set_extra(show_if_value_not=True)
    c = forms.BooleanField(
        label=_("Flag c"),
        help_text=_(
            "Clone message and execute the action(s) in a subprocess if the"
            + "conditions match. The parent process continues with the original"
            + "message after the clone process finishes."
        ),
        required=False,
        initial=False
    )
    A = forms.BooleanField(
        label=_("Flag A"),
        help_text=_("Execute this recipe if the previous recipe's conditions were met."),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    a = forms.BooleanField(
        label=_("Flag a"),
        help_text=_(
            "Execute this recipe if the previous recipe's conditions were"
            + "met and its action(s) were completed successfully."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    E = forms.BooleanField(
        label=_("Flag E"),
        help_text=_("Execute this recipe if the previous recipe's conditions were not met."),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    e = forms.BooleanField(
        label=_("Flag e"),
        help_text=_(
            "Execute this recipe if the previous recipe's conditions were met,"
            + "but its action(s) couldn't be completed."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    f = forms.BooleanField(
        label=_("Flag f"),
        help_text=_(
            "Feed the message to the pipeline on the action line if the conditions are met,"
            + "and continue processing with the output of the pipeline"
            + "(replacing the original message)."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    i = forms.BooleanField(
        label=_("Flag i"),
        help_text=_(
            "Suppress error checking when writing to a pipeline."
            + "This is typically used to get rid of SIGPIPE errors when the pipeline doesn't"
            + "eat all of the input Procmail wants to feed it."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    r = forms.BooleanField(
        label=_("Flag r"),
        help_text=_(
            """Raw mode: Don't do any "fixing" of the original message when writing it out"""
            + "(such as adding a final newline if the message didn't have one originally)."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    w = forms.BooleanField(
        label=_("Flag w"),
        help_text=_(
            "Wait for the program in the action line to finish before continuing."
            + "Otherwise, Procmail will spawn off the program and leave it executing on its own."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    W = forms.BooleanField(
        label=_("Flag W"),
        help_text=_(
            """Like w, but additionally suppresses any "program failure" messages"""
            + "from the action pipeline."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    D = forms.BooleanField(
        label=_("Flag D"),
        help_text=_(
            'Pay attention to character case when matching: "a" is treated as distinct from'
            + '"A" and so on. Some of the special macros are always matched case-insensitively.'
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)

    lockfile = forms.BooleanField(label=_("Use a lockfile"), required=False, initial=False)
    lockfile_path = forms.CharField(
        label=_('lockfile path'),
        max_length=256,
        required=False
    ).set_extra(show_if_value_not="")

    def clean(self):
        if not self.cleaned_data['h'] and not self.cleaned_data['b']:
            raise forms.ValidationError(
                "Please put at least the flag h or b or the recipe will do nothing"
            )
        if not self.cleaned_data['H'] and not self.cleaned_data['H']:
            raise forms.ValidationError(
                "Please put at least the flag H or B or the recipe will nether match"
            )


class ActionForm(forms.Form, HidableFieldsForm):

    action_type = forms.ChoiceField(
        label=_('Action type'),
        choices=[
            (procmail.ActionSave.type, _("Save the mail to")),
            (procmail.ActionForward.type, _("Forward the mail to")),
            (procmail.ActionShell.type, _("Pipe the mail to the shell")),
            (procmail.ActionNested.type, _("Execute multiple rules")),
        ]
    )

    action_param = forms.CharField(label=_('Parameter'), max_length=256, required=False)

    def clean(self):
        if self.cleaned_data["action_type"] in [
            procmail.ActionSave.type,
            procmail.ActionForward.type,
            procmail.ActionShell.type,
        ] and not self.cleaned_data.get("action_param"):
            raise forms.ValidationError(
                "Action %s require a parameter" % self.cleaned_data["action_type"]
            )

        if self.cleaned_data["action_type"] in [
                procmail.ActionSave.type,
                procmail.ActionShell.type
        ]:
            self.params = (self.cleaned_data["action_param"],)
        elif self.cleaned_data["action_type"] == procmail.ActionForward.type:
            param = self.cleaned_data["action_param"]
            if ',' in param:
                param = param.split(',')
            else:
                param = param.split()
            self.params = ([p.strip() for p in param],)
        elif self.cleaned_data["action_type"] == procmail.ActionNested.type:
            self.params = []


class ConditionForm(forms.Form):
    type = forms.TypedChoiceField(
        label=_('condition type'),
        choices=[
            ("", ""),
            (procmail.ConditionShell.type, _("Pipe the the shell command and expect 0 exit code")),
            (procmail.ConditionSize.type, _("Is bigger or lower than x bytes")),
            (procmail.ConditionRegex.type, _("Match the regular expression")),
        ],
        required=False,
    )
    negate = forms.BooleanField(label=_("negate"), required=False)
    param = forms.CharField(label=_('parameter'), max_length=256, required=False)
    substitute = forms.BooleanField(label=_("substitute"), required=False, initial=False)
    substitute_counter = forms.IntegerField(
        label=_("substitute counter"),
        initial=1
    ).set_extra(show_if_value_not=1)
    score = forms.BooleanField(
        label=_("score"),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    score_x = forms.IntegerField(
        label=_("score x"),
        initial=1,
        help_text=_("Score to add on the first match")
    ).set_extra(show_if_value_not=1)
    score_y = forms.IntegerField(
        label=_("score y"),
        initial=0,
        help_text=_("Score to add on subsequent matches")
    ).set_extra(show_if_value_not=0)
    variable = forms.BooleanField(
        label=_("variable"),
        required=False,
        initial=False,
        help_text=_("Match the condition agains a variable")
    ).set_extra(show_if_value_not=False)
    variable_name = forms.CharField(
        label=_('variable name'),
        max_length=256,
        required=False,
        initial=""
    ).set_extra(show_if_value_not="")

    def clean(self):
        param = self.cleaned_data["param"]

        if self.cleaned_data["type"] in [
            procmail.ConditionShell.type,
            procmail.ConditionSize.type,
            procmail.ConditionRegex.type
        ] and not param:
            raise forms.ValidationError(
                "Condition %s require a non null parameter" % self.cleaned_data["type"]
            )

        if self.cleaned_data["type"] == procmail.ConditionSize.type:
            if ('<' not in param and '>' not in param) or ('<' in param and '>' in param):
                raise forms.ValidationError(
                    "Condition %s parameter must be of " % self.cleaned_data["type"] +
                    "the shape (<|>) number"
                )

            sign = '<' if '<' in param else '>'
            size = param.replace(sign, '').strip()
            try:
                size = int(size)
            except ValueError:
                raise forms.ValidationError(
                    "Condition %s parameter must be of " % self.cleaned_data["type"] +
                    "the shape (<|>) number"
                )
            self.params = (sign, size)
        else:
            if self.cleaned_data["type"] == procmail.ConditionRegex.type:
                try:
                    re.compile(param)
                except re.error as e:
                    raise forms.ValidationError("Param is not a valid regular expression : %s" % e)
            self.params = (param, )

        if self.cleaned_data["substitute"] and self.cleaned_data["substitute_counter"] < 1:
            raise forms.ValidationError("substitute counter must be >= 1")


class AssignmentForm(forms.Form):
    variable_name = forms.CharField(label=_('variable name'), max_length=256)
    value = forms.CharField(label=_('value'), max_length=256, required=False)
    shell = forms.BooleanField(
        label=_("Shell eval"),
        help_text=_("Evaluate the value in a shell and store the ouput in the variable"),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)

    def clean(self):
        if self.cleaned_data["shell"] and self.cleaned_data["value"]:
            self.cleaned_data["quote"] = "`"
        elif self.cleaned_data["value"]:
            # if no space, no need of quotes
            if unicodeSpacesSet.isdisjoint(self.cleaned_data["value"]):
                self.cleaned_data["quote"] = None
            # we prefer double quote
            elif '"' not in self.cleaned_data["value"]:
                self.cleaned_data["quote"] = '"'
            # we prefer single quote on escaping quote
            elif "'" not in self.cleaned_data["value"]:
                self.cleaned_data["quote"] = "'"
            # if we must escape anyway, we prefer double quote
            else:
                self.cleaned_data["quote"] = '"'
        else:
            self.cleaned_data["quote"] = None


AssignmentFormSet = formset_factory(
    AssignmentForm,
    extra=1,
    formset=AssignmentBaseFormSet,
    can_delete=True
)
ConditionFormSet = formset_factory(ConditionForm, extra=1, can_delete=True)


class StatementForm(forms.Form):

    statement = forms.ChoiceField(widget=forms.RadioSelect, choices=[
        ('simple', _('Simple interface')),
        ('assignment', _('Assignment')),
        ('recipe', _('Recipe')),


    ])


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


AssignmentFormSet.show_init = show_init
ConditionFormSet.show_init = show_init


def conditions_form_initial(conditions):
    initials = []
    for cond in conditions:
        init = {
            'substitute': False,
            'substitute_counter': 1,
            'negate': False,
            'variable': False,
            'score': False,
            'score_x': 1,
            'score_y': 0
        }
        while cond.is_nested():
            if cond.is_negate():
                init['negate'] = not init['negate']
            elif cond.is_substitute():
                if init['substitute']:
                    init['substitute_counter'] += 1
                init['substitute'] = True
            elif cond.is_variable():
                init['variable'] = True
                init['variable_name'] = cond.variable
            elif cond.is_score():
                init['score'] = True
                init['score_x'] = cond.x
                init['score_y'] = cond.y
            cond = cond.condition

        init["type"] = cond.type
        if cond.is_shell():
            init["param"] = cond.cmd
        elif cond.is_size():
            init["param"] = cond.pre_render()
        elif cond.is_regex():
            init["param"] = cond.regex
        elif cond.is_score():
            init["param"] = cond.pre_render()

        initials.append(init)
    return initials


def assignment_form_initial(assignment):
    initials = []
    for (variable_name, value, quote) in assignment.variables:
        initials.append({
            'variable_name': variable_name,
            'value': value,
            'shell': (quote == '`'),
        })
    return initials


def meta_form_initial(obj):
    return {
        'title': obj.meta_title or obj.gen_title(),
        'comment': obj.meta_comment,
    }


def header_form_initial(recipe):
    lockfile = recipe.header.lockfile
    return {
        'H': recipe.header.H,
        'B': recipe.header.B,
        'h': recipe.header.h,
        'b': recipe.header.b,
        'c': recipe.header.c,
        'A': recipe.header.A,
        'a': recipe.header.a,
        'E': recipe.header.E,
        'e': recipe.header.e,
        'f': recipe.header.f,
        'i': recipe.header.i,
        'r': recipe.header.r,
        'w': recipe.header.w,
        'W': recipe.header.W,
        'D': recipe.header.D,

        'lockfile': True if lockfile else False,
        'lockfile_path': "" if isinstance(lockfile, bool) else lockfile,
    }


def action_form_initial(recipe):
    init = {
        'action_type': recipe.action.type,
    }
    if recipe.action.is_save():
        init['action_param'] = recipe.action.path
    if recipe.action.is_forward():
        init['action_param'] = " ".join(recipe.action.recipients)
    if recipe.action.is_shell():
        init['action_param'] = recipe.action.cmd
    return init
