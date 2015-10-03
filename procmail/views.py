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
from django.shortcuts import render, redirect
from django.utils.translation import ugettext as _
from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse
from django.contrib.formtools.wizard.views import SessionWizardView

from pyprocmail import procmail
from pyprocmail.parser import ParseException

import forms
import forms_initial
import utils


class CreateStatement(SessionWizardView):
    form_list = [
        ("choose", forms.StatementForm),
        ("metadata", forms.MetaForm),
        ("assignment", forms.AssignmentFormSet),
        ("header", forms.HeaderForm),
        ("conditions", forms.ConditionFormSet),
        ("action", forms.ActionForm),
        ("simple_condition_kind", forms.SimpleConditionKind),
        ("simple_conditions", forms.SimpleConditionSet),
        ("simple_actions", forms.SimpleActionSet),
    ]

    condition_dict = {
        "assignment": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "assignment"
        ),
        "header": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "recipe"
        ),
        "conditions": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "recipe"
        ),
        "action": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "recipe"
        ),
        "simple_condition_kind": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "simple"
        ),
        "simple_conditions": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("simple_condition_kind") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "simple" and
            wizard.get_cleaned_data_for_step("simple_condition_kind").get("kind") in ["and", "or"]
        ),
        "simple_actions": (
            lambda wizard: wizard.get_cleaned_data_for_step("choose") and
            wizard.get_cleaned_data_for_step("choose").get("statement") == "simple"
        ),
    }

    def get_template_names(self):
        return "procmail/create.html"

    def get_context_data(self, form, **kwargs):
        try:
            procmailrc = utils.get_procmailrc(self.request.user)
        except ParseException:
            pass
        context = super(CreateStatement, self).get_context_data(form=form, **kwargs)
        form_context = []
        for step, form in self.form_list.items():
            if self.steps.current == step:
                break
            form_context.append(self.get_cleaned_data_for_step(step))
        context.update({'form_data': form_context, 'procmailrc': procmailrc})
        return context

    def done(self, form_list, form_dict, **kwargs):
        typ = self.get_cleaned_data_for_step("choose")["statement"]
        try:
            procmailrc = utils.get_procmailrc(self.request.user)
        except ParseException as error:
            return parse_error(self.request, error)
        if typ == "recipe":
            return do_edit_recipe(
                self.request,
                self.kwargs['id'],
                None,
                procmailrc,
                form_dict["metadata"],
                form_dict["header"],
                form_dict["conditions"],
                form_dict["action"]
            )
        elif typ == "assignment":
            return do_edit_assignment(
                self.request,
                self.kwargs['id'],
                None,
                procmailrc,
                form_dict["metadata"],
                form_dict["assignment"]
            )
        elif typ == "simple":
            return do_simple(
                self.request,
                self.kwargs['id'],
                None,
                procmailrc,
                form_dict["metadata"],
                form_dict["simple_condition_kind"],
                form_dict.get("simple_conditions"),
                form_dict["simple_actions"]
            )


def do_simple(request, id, r, procmailrc, form_meta, form_cond_kind, form_cond, form_action):
    kind = form_cond_kind.cleaned_data["kind"]
    statements = form_action.statements
    title = form_meta.cleaned_data["title"]
    comment = form_meta.cleaned_data["comment"]
    r = utils.make_simple_rules(
        kind,
        title,
        comment,
        statements,
        form_cond.conditions if form_cond else None
    )
    procmailrc.append(r)
    utils.set_procmailrc(request.user, procmailrc)
    return redirect("procmail:index")


@login_required
def index(request):
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    return render(request, "procmail/index.html", utils.context({"procmailrc": procmailrc}))


@login_required
def download(request):
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    return HttpResponse(
        procmailrc.render().encode("utf-8"),
        content_type="text/plain; charset=utf-8"
    )


def do_edit_recipe(
    request,
    id,
    r,
    procmailrc,
    form_meta,
    form_header,
    form_condition,
    form_action,
    create=False,
    delete=False
):
            if r is None:
                r = procmail.Recipe(procmail.Header(), procmail.Action())
                r.parent = get_rule(procmailrc, id)
                r.parent.append(r)
                if id:
                    r.id = "%s.%s" % (id, len(r.parent) - 1)
                else:
                    r.id = "%s" % (len(r.parent) - 1)
                id = r.id
            if form_meta.is_valid() and form_header.is_valid() \
                    and form_action.is_valid() and form_condition.is_valid():
                # header
                r.header.H = form_header.cleaned_data['H']
                r.header.B = form_header.cleaned_data['B']
                r.header.h = form_header.cleaned_data['h']
                r.header.b = form_header.cleaned_data['b']
                r.header.c = form_header.cleaned_data['c']
                r.header.A = form_header.cleaned_data['A']
                r.header.a = form_header.cleaned_data['a']
                r.header.E = form_header.cleaned_data['E']
                r.header.e = form_header.cleaned_data['e']
                r.header.f = form_header.cleaned_data['f']
                r.header.i = form_header.cleaned_data['i']
                r.header.r = form_header.cleaned_data['r']
                r.header.w = form_header.cleaned_data['w']
                r.header.W = form_header.cleaned_data['W']
                r.header.D = form_header.cleaned_data['D']
                r.meta_title = form_meta.cleaned_data['title']
                r.meta_comment = form_meta.cleaned_data['comment']
                if form_header.cleaned_data['lockfile']:
                    if form_header.cleaned_data['lockfile_path']:
                        r.header.lockfile = form_header.cleaned_data['lockfile_path']
                    else:
                        r.header.lockfile = True
                else:
                    r.header.lockfile = False
                # conditions
                conditions = []
                for fcond in form_condition:
                    if fcond.cleaned_data.get('DELETE', False):
                        continue
                    if not fcond.cleaned_data.get('type'):
                        continue
                    cond = procmail.Condition.from_type(fcond.cleaned_data['type'])(*fcond.params)
                    if fcond.cleaned_data['negate']:
                        cond = procmail.ConditionNegate(cond)
                    if fcond.cleaned_data['score']:
                        cond = procmail.ConditionScore(
                            fcond.cleaned_data['score_x'],
                            fcond.cleaned_data['score_y'],
                            cond
                        )
                    if fcond.cleaned_data['substitute']:
                        for i in range(fcond.cleaned_data['substitute_counter']):
                            cond = procmail.ConditionSubstitute(cond)
                    if fcond.cleaned_data['variable']:
                        cond = procmail.ConditionVariable(
                            fcond.cleaned_data['variable_name'],
                            cond
                        )
                    conditions.append(cond)
                r.conditions = conditions
                # action
                if form_action.cleaned_data['action_type'] != r.action.type or \
                        form_action.cleaned_data['action_type'] != procmail.ActionNested.type:
                    r.action = procmail.Action.from_type(
                        form_action.cleaned_data['action_type']
                    )(*form_action.params)
                if create:
                    utils.set_procmailrc(request.user, procmailrc)
                    return redirect("procmail:create", id=id)
                if delete:
                    r.parent.remove(r)
                    utils.set_procmailrc(request.user, procmailrc)
                    return redirect("procmail:edit", id=".".join(id.split('.')[:-1]))
                utils.set_procmailrc(request.user, procmailrc)
                return redirect("procmail:edit", id=id)


def do_edit_assignment(request, id, r, procmailrc, form_meta, form_assignment, delete=False):
            if r is None:
                r = procmail.Assignment([])
                r.parent = get_rule(procmailrc, id)
                r.parent.append(r)
                if id:
                    r.id = "%s.%s" % (id, len(r.parent) - 1)
                else:
                    r.id = "%s" % (len(r.parent) - 1)
                id = r.id
            if form_meta.is_valid() and form_assignment.is_valid():
                r.meta_title = form_meta.cleaned_data['title']
                r.meta_comment = form_meta.cleaned_data['comment']
                if not delete and form_assignment.variables:
                    r.variables = form_assignment.variables
                    utils.set_procmailrc(request.user, procmailrc)
                    return redirect("procmail:edit", id=id)
                else:
                    r.parent.remove(r)
                    utils.set_procmailrc(request.user, procmailrc)
                    return redirect("procmail:edit", id=".".join(id.split('.')[:-1]))


def get_rule(procmailrc, id):
    ids = id.split('.')
    print "%r" % id
    if id == "":
        return procmailrc
    r = procmailrc
    try:
        for i in ids:
            r = r[int(i)]
    except (TypeError, IndexError):
        raise Http404()
    return r


def parse_error(request, error):
    error_msg = _("""Fail to parse your procmailrc. You probably have a syntax error
near %(line)s at line %(lineno)s, column %(col)s.""") % {
        'line': repr(error.line)[1:],
        'lineno': error.lineno,
        'col': error.col
    }
    return render(request, "procmail/parse_error.html", {'error_msg': error_msg, 'error': error})


@login_required
def edit_simple(request, id):
    if not id:
        return redirect("procmail:index")
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    r = get_rule(procmailrc, id)
    if not r.django['is_simple']:
        return redirect("procmail:edit", id=id)

    initials = r.django['initials']

    if request.method == 'POST':
        form_meta = forms.MetaForm(
            request.POST,
            initial=initials['meta'],
            prefix="meta"
        )
        form_cond_kind = forms.SimpleConditionKind(
            request.POST,
            initial=initials['condition_kind'],
            prefix="condition_kind"
        )
        form_cond = forms.SimpleConditionSet(
            request.POST,
            initial=initials['conditions'],
            prefix="conditions"
        )
        form_action = forms.SimpleActionSet(
            request.POST,
            initial=initials['actions'],
            prefix="actions"
        )

        if all(form.is_valid() for form in [form_meta, form_cond_kind, form_cond, form_action]):
            kind = form_cond_kind.cleaned_data["kind"]
            statements = form_action.statements
            title = form_meta.cleaned_data["title"]
            comment = form_meta.cleaned_data["comment"]
            r_new = utils.make_simple_rules(
                kind,
                title,
                comment,
                statements,
                form_cond.conditions if form_cond else None
            )
            r.parent[int(id.split('.')[-1])] = r_new
            utils.set_procmailrc(request.user, procmailrc)
            return redirect("procmail:edit_simple", id=id)
    else:
        form_meta = forms.MetaForm(initial=initials['meta'], prefix="meta")
        form_cond_kind = forms.SimpleConditionKind(
            initial=initials['condition_kind'],
            prefix="condition_kind"
        )
        form_cond = forms.SimpleConditionSet(initial=initials['conditions'], prefix="conditions")
        form_action = forms.SimpleActionSet(initial=initials['actions'], prefix="actions")

    params = {
        'form_meta': form_meta,
        'form_cond_kind': form_cond_kind,
        'form_cond': form_cond,
        'form_action': form_action,
        'procmailrc': procmailrc,
        'curr_stmt': r,
    }

    return render(request, "procmail/edit_simple.html", utils.context(params))


@login_required
def edit(request, id):
    if not id:
        return redirect("procmail:index")
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    r = get_rule(procmailrc, id)

    params = {"procmailrc": procmailrc, "curr_stmt": r}
    if request.method == 'POST':
        if r.is_recipe():
            form_meta = forms.MetaForm(
                request.POST,
                initial=forms_initial.meta_form(r),
                prefix="meta"
            )
            form_header = forms.HeaderForm(
                request.POST,
                initial=forms_initial.header_form(r),
                prefix="header"
            )
            form_action = forms.ActionForm(
                request.POST,
                initial=forms_initial.action_form(r),
                prefix="action"
            )
            form_condition = forms.ConditionFormSet(
                request.POST,
                initial=forms_initial.conditions_form(r.conditions),
                prefix="condition"
            )
            params["form_meta"] = form_meta
            params["form_header"] = form_header
            params["form_action"] = form_action
            params["form_condition"] = form_condition
            ret = do_edit_recipe(
                request,
                id,
                r,
                procmailrc,
                form_meta,
                form_header,
                form_condition,
                form_action,
                create=("action_add" in request.POST),
                delete=("delete_stmt" in request.POST)
            )
            if ret:
                return ret
        elif r.is_assignment():
            form_meta = forms.MetaForm(
                request.POST,
                initial=forms_initial.meta_form(r),
                prefix="meta"
            )
            form_assignment = forms.AssignmentFormSet(
                request.POST,
                initial=forms_initial.assignment_form(r),
                prefix="assignment"
            )
            params["form_meta"] = form_meta
            params["form_assignment"] = form_assignment
            ret = do_edit_assignment(
                request,
                id,
                r,
                procmailrc,
                form_meta,
                form_assignment,
                delete=("delete_stmt" in request.POST)
            )
            if ret:
                return ret
    else:
        if r.is_recipe():
            form_meta = forms.MetaForm(initial=forms_initial.meta_form(r), prefix="meta")
            form_header = forms.HeaderForm(initial=forms_initial.header_form(r), prefix="header")
            form_action = forms.ActionForm(initial=forms_initial.action_form(r), prefix="action")
            form_condition = forms.ConditionFormSet(
                initial=forms_initial.conditions_form(r.conditions),
                prefix="condition"
            )
            params["form_meta"] = form_meta
            params["form_header"] = form_header
            params["form_action"] = form_action
            params["form_condition"] = form_condition
        elif r.is_assignment():
            form_meta = forms.MetaForm(initial=forms_initial.meta_form(r), prefix="meta")
            form_assignment = forms.AssignmentFormSet(
                initial=forms_initial.assignment_form(r),
                prefix="assignment"
            )
            params["form_meta"] = form_meta
            params["form_assignment"] = form_assignment
    return render(request, "procmail/edit.html", utils.context(params))


@login_required
def up(request, id, cur_id):
    return up_down(request, id, cur_id, lambda x, y: x-y, lambda ids, r: ids[-1] == "0")


@login_required
def down(request, id, cur_id):
    return up_down(request, id, cur_id, lambda x, y: x+y, lambda ids, r: int(ids[-1]) == len(r) - 1)


def up_down(request, id, cur_id, op, test):
    ids = id.split('.')

    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    r = procmailrc
    try:
        for i in ids[:-1]:
            r = r[int(i)]
    except (TypeError, IndexError):
        raise Http404()

    if test(ids, r):
        if not cur_id:
            return redirect("procmail:index")
        else:
            return redirect("procmail:edit", id=cur_id)

    i = int(ids[-1])
    j = op(i, 1)
    while j > 0 and j < len(r) and r[j].is_comment():
        j = op(j, 1)
    if r[j].is_comment():
        return redirect("procmail:edit", id=cur_id)
    r[j], r[i] = r[i], r[j]
    new_id = ".".join(ids[:-1] + ["%s" % j])
    utils.set_procmailrc(request.user, procmailrc)
    if not cur_id:
        return redirect("procmail:index")
    else:
        return redirect("procmail:edit", id=cur_id if id != cur_id else new_id)
