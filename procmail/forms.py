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

from pyprocmail import procmail
from pyprocmail.procmail import Header


def set_extra(self, **kwargs):
    self.extra = kwargs
    return self


forms.Field.set_extra = set_extra
forms.Field.extra = {}


class MetaForm(forms.Form):
    title = forms.CharField(label='title', max_length=100)
    comment = forms.CharField(label='comment', max_length=256, required=False)


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
        label="Flag H",
        help_text=Header.H.__doc__,
        required=False,
        initial=True
    ).set_extra(show_if_value_not=True)
    B = forms.BooleanField(
        label="Flag B",
        help_text=Header.B.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    h = forms.BooleanField(
        label="Flag h",
        help_text=Header.h.__doc__,
        required=False,
        initial=True
    ).set_extra(show_if_value_not=True)
    b = forms.BooleanField(
        label="Flag b",
        help_text=Header.b.__doc__,
        required=False,
        initial=True
    ).set_extra(show_if_value_not=True)
    c = forms.BooleanField(
        label="Flag c",
        help_text=Header.c.__doc__,
        required=False,
        initial=False
    )
    A = forms.BooleanField(
        label="Flag A",
        help_text=Header.A.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    a = forms.BooleanField(
        label="Flag a",
        help_text=Header.a.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    E = forms.BooleanField(
        label="Flag E",
        help_text=Header.E.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    e = forms.BooleanField(
        label="Flag e",
        help_text=Header.e.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    f = forms.BooleanField(
        label="Flag f",
        help_text=Header.f.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    i = forms.BooleanField(
        label="Flag i",
        help_text=Header.i.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    r = forms.BooleanField(
        label="Flag r",
        help_text=Header.r.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    w = forms.BooleanField(
        label="Flag w",
        help_text=Header.w.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    W = forms.BooleanField(
        label="Flag W",
        help_text=Header.W.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    D = forms.BooleanField(
        label="Flag D",
        help_text=Header.D.__doc__,
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)

    lockfile = forms.BooleanField(label="Use a lockfile", required=False, initial=False)
    lockfile_path = forms.CharField(
        label='lockfile path',
        max_length=256,
        required=False
    ).set_extra(show_if_value_not="")

    def clean(self):
        if not self.cleaned_data['h'] and not self.cleaned_data['b']:
            raise forms.ValidationError("Please put at least the flag h or b or the recipe will do nothing")
        if not self.cleaned_data['H'] and not self.cleaned_data['H']:
            raise forms.ValidationError("Please put at least the flag H or B or the recipe will nether match")


class ActionForm(forms.Form, HidableFieldsForm):

    action_type = forms.ChoiceField(
        label='Action type',
        choices=[
            (procmail.ActionSave.type, "save"),
            (procmail.ActionForward.type, "forward"),
            (procmail.ActionShell.type, "shell"),
            (procmail.ActionNested.type, "nested"),
        ]
    )

    action_param = forms.CharField(label='Parameter', max_length=256, required=False)

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
        label='condition type',
        choices=[
            ("", ""),
            (procmail.ConditionShell.type, "shell"),
            (procmail.ConditionSize.type, "size"),
            (procmail.ConditionRegex.type, "regex"),
        ],
        required=False,
    )
    negate = forms.BooleanField(label="negate", required=False)
    param = forms.CharField(label='parameter', max_length=256, required=False)
    substitute = forms.BooleanField(label="substitute", required=False, initial=False)
    substitute_counter = forms.IntegerField(
        label="substitute counter",
        initial=1
    ).set_extra(show_if_value_not=1)
    score = forms.BooleanField(
        label="score",
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    score_x = forms.IntegerField(label="score x", initial=1).set_extra(show_if_value_not=1)
    score_y = forms.IntegerField(label="score y", initial=0).set_extra(show_if_value_not=0)
    variable = forms.BooleanField(
        label="variable",
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)
    variable_name = forms.CharField(
        label='variable name',
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
            size = param.replace(self.sign, '').strip()
            try:
                size = int(size)
            except ValueError:
                raise forms.ValidationError(
                    "Condition %s parameter must be of " % self.cleaned_data["type"] +
                    "the shape (<|>) number"
                )
            self.params = (sign, size)
        else:
            self.params = (param, )

        if self.cleaned_data["substitute"] and self.cleaned_data["substitute_counter"] < 1:
            raise forms.ValidationError("substitute counter must be >= 1")


class AssignmentForm(forms.Form):
    variable_name = forms.CharField(label='variable name', max_length=256)
    value = forms.CharField(label='value', max_length=256, required=False)
    shell = forms.BooleanField(
        label="Shell eval",
        required=False,
        initial=False
    ).set_extra(show_if_value_not=False)

    def clean(self):
        if self.cleaned_data["shell"] and self.cleaned_data["value"]:
            self.cleaned_data["quote"] = "`"
        elif self.cleaned_data["value"]:
            if "'" not in self.cleaned_data["value"]:
                self.cleaned_data["quote"] = "'"
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
        ('assignment', 'Assignment'),
        ('recipe', 'Recipe'),


    ])


def show(self, field_name):
    try:
        if field_name in self._show_dict:
            return self._show_dict[field_name]
    except AttributeError:
        self._show_dict = {}

    i = 0
    for form in self:
        if form.data and form.add_prefix(field_name) in form.data:
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
        'title': obj.meta_title,
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
