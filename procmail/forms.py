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
from django.utils.translation import ugettext_lazy as _

import re
import collections

import utils
from pyprocmail import procmail


forms.Field.set_extra = utils.set_extra
forms.Field.extra = {}

class DeleteStatement(forms.Form):
    def __init__(self, *args, **kwargs):
        self.statement = kwargs.pop('statement', None)
        super(DeleteStatement, self).__init__(*args, **kwargs)

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


class SimpleCondition(forms.Form):

    conditions = None

    object = forms.ChoiceField(
        label=_('Scope'),
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

    custom_header = forms.CharField(label=_('Custom header'), max_length=256, required=False)

    match = forms.ChoiceField(
        label=_('Match'),
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

    param = forms.CharField(label=_('Parameter'), max_length=256, required=False)

    def clean_custom_header(self):
        if ':' in self.cleaned_data["custom_header"]:
            raise forms.ValidationError(_("A header name cannot contain ':'"))
        return self.cleaned_data["custom_header"].strip()

    def clean(self):
        data = self.cleaned_data
        if not data.get("match") or data.get('DELETE', False):
            return
        if data['object'] == "custom_header" and not data["custom_header"]:
            raise forms.ValidationError(_("Please specify a custom header"))
        if data["match"] not in ["exists", "not_exists"] and not data["param"]:
            raise forms.ValidationError(_("Please specify a parameter"))
        if data["match"] in ["size_g", "size_l"]:
            try:
                data["param"] = int(data["param"].strip())
            except ValueError:
                raise forms.validationError(_("Parameter must be a whole number of byte"))
        if data["match"] in ["regex", "not_regex"]:
            try:
                re.compile(data["param"])
            except re.error as error:
                raise forms.validationError(_("Bad regular expression : %s") % error)

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
            prefix = "^%s:[ ]*" % utils.escape_re(data["custom_header"])
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
                regex = "%s.*%s.*" % (prefix, utils.escape_re(data["param"]))
            elif match == "equal":
                regex = "%s%s$" % (prefix, utils.escape_re(data["param"]))
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
            raise forms.ValidationError(_("Should not happening, contact an administrator 1"))


class SimpleConditionBaseSet(BaseFormSet):
    def clean(self):
        conditions = collections.defaultdict(list)
        for form in self.forms:
            if form.errors:
                return
            if form.conditions is not None:
                conditions[form.flags].extend(form.conditions)
        self.conditions = conditions.items()


SimpleConditionSet = formset_factory(
    SimpleCondition,
    extra=1,
    formset=SimpleConditionBaseSet,
    can_delete=True
)


class SimpleAction(forms.Form):
    statement = None

    action = forms.ChoiceField(
        label=_('Action'),
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

    param = forms.CharField(label=_('Parameter'), max_length=256, required=False)
    variable_name = forms.CharField(label=_('Variable name'), max_length=256, required=False)
    variable_value = forms.CharField(label=_('Variable value'), max_length=256, required=False)

    def clean(self):
        data = self.cleaned_data
        if not data['action'] or data.get('DELETE', False):
            return
        if data['action'] in ["save", "copy", "redirect", "redirect_copy"] and not data['param']:
            raise forms.ValidationError(_("Please specify a %s") % self.param.label)
        if data['action'] == "variable" and not data["variable_name"]:
            raise forms.ValidationError(_("Please specify a %s") % self.variable_name.label)

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
            raise forms.ValidationError(_("Should not happening, contact an administrator 2"))


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
                _("You need at least one assignement on a assignement satement")
            )
        self.variables = variables


class HeaderForm(forms.Form, utils.HidableFieldsForm):

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
            "Clone message and execute the action(s) in a subprocess if the "
            + "conditions match. The parent process continues with the original "
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
            "Execute this recipe if the previous recipe's conditions were "
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
            "Execute this recipe if the previous recipe's conditions were met, "
            + "but its action(s) couldn't be completed."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    f = forms.BooleanField(
        label=_("Flag f"),
        help_text=_(
            "Feed the message to the pipeline on the action line if the conditions are met, "
            + "and continue processing with the output of the pipeline "
            + "(replacing the original message)."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    i = forms.BooleanField(
        label=_("Flag i"),
        help_text=_(
            "Suppress error checking when writing to a pipeline. "
            + "This is typically used to get rid of SIGPIPE errors when the pipeline doesn't "
            + "eat all of the input Procmail wants to feed it."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    r = forms.BooleanField(
        label=_("Flag r"),
        help_text=_(
            """Raw mode: Don't do any "fixing" of the original message when writing it out """
            + "(such as adding a final newline if the message didn't have one originally)."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    w = forms.BooleanField(
        label=_("Flag w"),
        help_text=_(
            "Wait for the program in the action line to finish before continuing. "
            + "Otherwise, Procmail will spawn off the program and leave it executing on its own."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    W = forms.BooleanField(
        label=_("Flag W"),
        help_text=_(
            """Like w, but additionally suppresses any "program failure" messages """
            + "from the action pipeline."
        ),
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    D = forms.BooleanField(
        label=_("Flag D"),
        help_text=_(
            'Pay attention to character case when matching: "a" is treated as distinct from '
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
                _("Please put at least the flag h or b or the recipe will do nothing")
            )
        if not self.cleaned_data['H'] and not self.cleaned_data['H']:
            raise forms.ValidationError(
                _("Please put at least the flag H or B or the recipe will nether match")
            )


class ActionForm(forms.Form, utils.HidableFieldsForm):

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
                _("Action %s require a parameter") % self.cleaned_data["action_type"]
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
            (procmail.ConditionShell.type, _("Pipe to the shell command and expect 0 exit code")),
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
                _("Condition %s require a non null parameter") % self.cleaned_data["type"]
            )

        if self.cleaned_data["type"] == procmail.ConditionSize.type:
            if ('<' not in param and '>' not in param) or ('<' in param and '>' in param):
                raise forms.ValidationError(
                    _(
                        "Condition %s parameter must be of the shape (<|>) number"
                    ) % self.cleaned_data["type"]
                )

            sign = '<' if '<' in param else '>'
            size = param.replace(sign, '').strip()
            try:
                size = int(size)
            except ValueError:
                raise forms.ValidationError(
                    _(
                        "Condition %s parameter must be of the shape (<|>) number"
                    ) % self.cleaned_data["type"]
                )
            self.params = (sign, size)
        else:
            if self.cleaned_data["type"] == procmail.ConditionRegex.type:
                try:
                    re.compile(param)
                except re.error as e:
                    raise forms.ValidationError(
                        _("Param is not a valid regular expression : %s") % e
                    )
            self.params = (param, )

        if self.cleaned_data["substitute"] and self.cleaned_data["substitute_counter"] < 1:
            raise forms.ValidationError(_("substitute counter must be >= 1"))


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
            if utils.unicodeSpacesSet.isdisjoint(self.cleaned_data["value"]):
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

    statement = forms.ChoiceField(
        label="",
        widget=forms.RadioSelect,
        choices=[
            ('simple', _('Simple interface')),
            ('assignment', _('Assignment')),
            ('recipe', _('Recipe')),
        ]
    )


AssignmentFormSet.show_init = utils.show_init
ConditionFormSet.show_init = utils.show_init
