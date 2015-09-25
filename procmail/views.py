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
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.contrib.formtools.wizard.views import SessionWizardView

import os
import shutil

import pyprocmail.procmail
from pyprocmail import procmail
import forms

def get_procmailrc(user):
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

    return pyprocmail.procmail.parse(procmailrc_path)



class CreateStatement(SessionWizardView):
    form_list = [
        ("choose", forms.StatementForm),
        ("metadata", forms.MetaForm),
        ("assignment", forms.AssignmentFormSet),
        ("header", forms.HeaderForm),
        ("conditions", forms.ConditionFormSet),
        ("action", forms.ActionForm),
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
    }

    def get_template_names(self):
        return "procmail/create.html"

    def get_context_data(self, form, **kwargs):
        context = super(CreateStatement, self).get_context_data(form=form, **kwargs)
        form_context = []
        for step, form in self.form_list.items():
            if self.steps.current == step:
                break
            form_context.append(self.get_cleaned_data_for_step(step))
        context.update({'form_data': form_context})
        return context

    def done(self, form_list, form_dict, **kwargs):
        typ = self.get_cleaned_data_for_step("choose")["statement"]
        procmailrc = get_procmailrc(self.request.user)
        if typ == "recipe":
            return do_edit_recipe(
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
                self.kwargs['id'],
                None,
                procmailrc,
                form_dict["metadata"],
                form_dict["assignment"]
            )


@login_required
def index(request):
    procmailrc = get_procmailrc(request.user)
    return render(request, "procmail/index.html", {"procmailrc": procmailrc})


def do_edit_recipe(
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
                if r.parent.id:
                    r.id = "%s.%s" % (r.parent.id, len(r.parent) - 1)
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
                    procmailrc.write("/home/valentin/.procmailrc")
                    return redirect("procmail:create", id=id)
                if delete:
                    r.parent.remove(r)
                    procmailrc.write("/home/valentin/.procmailrc")
                    return redirect("procmail:edit", id=".".join(id.split('.')[:-1]))
                procmailrc.write("/home/valentin/.procmailrc")
                return redirect("procmail:edit", id=id)


def do_edit_assignment(id, r, procmailrc, form_meta, form_assignment, delete=False):
            if r is None:
                r = procmail.Assignment([])
                r.parent = get_rule(procmailrc, id)
                r.parent.append(r)
                if r.id:
                    r.id = "%s.%s" % (r.parent.id, len(r.parent) - 1)
                else:
                    r.id = "%s" % (len(r.parent) - 1)
                id = r.id
            if form_meta.is_valid() and form_assignment.is_valid():
                r.meta_title = form_meta.cleaned_data['title']
                r.meta_comment = form_meta.cleaned_data['comment']
                if not delete and form_assignment.variables:
                    r.variables = form_assignment.variables
                    procmailrc.write("/home/valentin/.procmailrc")
                    return redirect("procmail:edit", id=id)
                else:
                    r.parent.remove(r)
                    procmailrc.write("/home/valentin/.procmailrc")
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


@login_required
def edit(request, id):
    if not id:
        return redirect("procmail:index")
    procmailrc = get_procmailrc(request.user)
    r = get_rule(procmailrc, id)

    params = {"procmailrc": procmailrc, "curr_stmt": r}
    if request.method == 'POST':
        if r.is_recipe():
            form_meta = forms.MetaForm(
                request.POST,
                initial=forms.meta_form_initial(r),
                prefix="meta"
            )
            form_header = forms.HeaderForm(
                request.POST,
                initial=forms.header_form_initial(r),
                prefix="header"
            )
            form_action = forms.ActionForm(
                request.POST,
                initial=forms.action_form_initial(r),
                prefix="action"
            )
            form_condition = forms.ConditionFormSet(
                request.POST,
                initial=forms.conditions_form_initial(r.conditions),
                prefix="condition"
            )
            params["form_meta"] = form_meta
            params["form_header"] = form_header
            params["form_action"] = form_action
            params["form_condition"] = form_condition
            ret = do_edit_recipe(
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
                initial=forms.meta_form_initial(r),
                prefix="meta"
            )
            form_assignment = forms.AssignmentFormSet(
                request.POST,
                initial=forms.assignment_form_initial(r),
                prefix="assignment"
            )
            params["form_meta"] = form_meta
            params["form_assignment"] = form_assignment
            ret = do_edit_assignment(
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
            form_meta = forms.MetaForm(initial=forms.meta_form_initial(r), prefix="meta")
            form_header = forms.HeaderForm(initial=forms.header_form_initial(r), prefix="header")
            form_action = forms.ActionForm(initial=forms.action_form_initial(r), prefix="action")
            form_condition = forms.ConditionFormSet(
                initial=forms.conditions_form_initial(r.conditions),
                prefix="condition"
            )
            params["form_meta"] = form_meta
            params["form_header"] = form_header
            params["form_action"] = form_action
            params["form_condition"] = form_condition
        elif r.is_assignment():
            form_meta = forms.MetaForm(initial=forms.meta_form_initial(r), prefix="meta")
            form_assignment = forms.AssignmentFormSet(
                initial=forms.assignment_form_initial(r),
                prefix="assignment"
            )
            params["form_meta"] = form_meta
            params["form_assignment"] = form_assignment
    return render(request, "procmail/edit.html", params)


@login_required
def up(request, id, cur_id):
    return up_down(request, id, cur_id, lambda x, y: x-y, lambda ids, r: ids[-1] == "0")


@login_required
def down(request, id, cur_id):
    return up_down(request, id, cur_id, lambda x, y: x+y, lambda ids, r: int(ids[-1]) == len(r) - 1)


def up_down(request, id, cur_id, op, test):
    ids = id.split('.')

    procmailrc = get_procmailrc(request.user)
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
    procmailrc.write("/home/valentin/.procmailrc")
    if not cur_id:
        return redirect("procmail:index")
    else:
        return redirect("procmail:edit", id=cur_id if id != cur_id else new_id)
