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
from django.http import Http404, HttpResponse, HttpResponseServerError
from django.core.urlresolvers import reverse
from django.views.decorators.csrf import csrf_exempt

try:
    from django.contrib.formtools.wizard.views import SessionWizardView
except ImportError:
    from formtools.wizard.views import SessionWizardView

from pyprocmail.parser import ParseException

import forms
import utils
import json


def delete(request, id, view_name, curr_id=None):
    if curr_id == id:
        curr_id = None
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    try:
        r = procmailrc[id]
        curr_stmt = procmailrc[curr_id if curr_id is not None else id]
    except KeyError:
        raise Http404()
    if request.method == 'POST':
        form = forms.DeleteStatement(request.POST, statement=r)
        if form.is_valid():
            id = r.delete()
            utils.set_procmailrc(request.user, procmailrc)
        return redirect("procmail:%s" % view_name, id=(curr_id if curr_id else id))
    else:
        form = forms.DeleteStatement(statement=r)
        params = {
            'form': form,
            'curr_stmt': curr_stmt,
            'procmailrc': procmailrc,
            'view_name': view_name,
            'type': _('assignement') if r.is_assignment() else _("recipe"),
            'title': r.meta_title if r.meta_title else r.gen_title(),
        }
        return render(request, "procmail/delete.html", utils.context(request, params))


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
        "assignment": utils.wizard_switch_by_stmt("assignment"),
        "header": utils.wizard_switch_by_stmt("recipe"),
        "conditions": utils.wizard_switch_by_stmt("recipe"),
        "action": utils.wizard_switch_by_stmt("recipe"),
        "simple_condition_kind": utils.wizard_switch_by_stmt("simple"),
        "simple_conditions": utils.wizard_switch_by_stmt(
            "simple",
            utils.wizard_switch_by_kinds(["and", "or"])
        ),
        "simple_actions": utils.wizard_switch_by_stmt("simple"),
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
        return utils.context(self.request, context)

    def done(self, form_list, form_dict, **kwargs):
        typ = self.get_cleaned_data_for_step("choose")["statement"]
        try:
            procmailrc = utils.get_procmailrc(self.request.user)
        except ParseException as error:
            return parse_error(self.request, error)
        if typ == "recipe":
            r = utils.make_recipe(procmailrc, self.kwargs['id'])
            utils.update_recipe(
                r,
                form_dict["metadata"].cleaned_data['title'],
                form_dict["metadata"].cleaned_data['comment'],
                form_dict["header"].header,
                form_dict["action"].action,
                form_dict["conditions"].conditions
            )
            utils.set_procmailrc(self.request.user, procmailrc)
            return redirect("procmail:edit", id=r.id)
        elif typ == "assignment":
            r = utils.make_assignment(procmailrc, self.kwargs['id'])
            utils.update_assignment(
                r,
                form_dict["metadata"].cleaned_data['title'],
                form_dict["metadata"].cleaned_data['comment'],
                form_dict["assignment"].variables
            )
            utils.set_procmailrc(self.request.user, procmailrc)
            return redirect("procmail:edit", id=r.id)
        elif typ == "simple":
            try:
                conditions = form_dict["simple_conditions"].conditions
            except KeyError:
                conditions = None
            r = utils.make_simple_rules(
                form_dict["simple_condition_kind"].cleaned_data["kind"],
                form_dict["metadata"].cleaned_data['title'],
                form_dict["metadata"].cleaned_data['comment'],
                form_dict["simple_actions"].statements,
                conditions
            )
            try:
                r.parent = procmailrc[self.kwargs['id']]
            except KeyError:
                raise Http404()
            r.parent.append(r)
            utils.set_procmailrc(self.request.user, procmailrc)
            return redirect("procmail:edit_simple", id=r.id)


@login_required
def index(request, id=None):
    if id is not None:
        return redirect("procmail:index")
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    return render(
        request,
        "procmail/index.html",
        utils.context(request, {"procmailrc": procmailrc, 'simple': True})
    )


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


def parse_error(request, error):
    params = {
        'line': repr(error.line)[1:],
        'lineno': error.lineno,
        'col': error.col,
        'error': error
    }
    return render(
        request,
        "procmail/parse_error.html",
        utils.context(request, params)
    )


@login_required
def edit_simple(request, id):
    if not id:
        return redirect("procmail:index")
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    try:
        r = procmailrc[id]
    except KeyError:
        raise Http404()
    if not r.django['is_simple']:
        return redirect("procmail:edit", id=id)
    if r.parent.django['is_simple']:
        return redirect("procmail:edit_simple", id=r.parent.id)

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
        if "delete_stmt" in request.POST:
            return redirect("procmail:delete", id=id, view_name="edit_simple")
        elif all(form.is_valid() for form in [form_meta, form_cond_kind, form_cond, form_action]):
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
        'simple': True,
        'form_meta': form_meta,
        'form_cond_kind': form_cond_kind,
        'form_cond': form_cond,
        'form_action': form_action,
        'procmailrc': procmailrc,
        'curr_stmt': r,
    }

    return render(request, "procmail/edit_simple.html", utils.context(request, params))


@login_required
def edit(request, id):
    if not id:
        return redirect("procmail:index")
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException as error:
        return parse_error(request, error)
    try:
        r = procmailrc[id]
    except KeyError:
        raise Http404()

    params = {"procmailrc": procmailrc, "curr_stmt": r}
    if request.method == 'POST':
        if r.is_recipe():
            params["form_meta"] = forms.MetaForm(request.POST, statement=r, prefix="meta")
            params["form_header"] = forms.HeaderForm(request.POST, header=r.header, prefix="header")
            params["form_action"] = forms.ActionForm(request.POST, action=r.action, prefix="action")
            params["form_condition"] = forms.ConditionFormSet(
                request.POST,
                conditions=r.conditions,
                prefix="condition"
            )
            if "delete_stmt" in request.POST:
                return redirect("procmail:delete", id=id, view_name="edit")
            elif all(form.is_valid() for key, form in params.items() if key.startswith("form_")):
                utils.update_recipe(
                    r,
                    params["form_meta"].cleaned_data['title'],
                    params["form_meta"].cleaned_data['comment'],
                    params["form_header"].header,
                    params["form_action"].action,
                    params["form_condition"].conditions
                )
                utils.set_procmailrc(request.user, procmailrc)
                if "action_add" in request.POST:
                    return redirect("procmail:create", id=id)
                else:
                    return redirect("procmail:edit", id=id)
        elif r.is_assignment():
            params["form_meta"] = forms.MetaForm(request.POST, statement=r, prefix="meta")
            params["form_assignment"] = forms.AssignmentFormSet(
                request.POST,
                assignment=r,
                prefix="assignment"
            )
            if "delete_stmt" in request.POST:
                return redirect("procmail:delete", id=id, view_name="edit")
            elif all(form.is_valid() for key, form in params.items() if key.startswith("form_")):
                utils.update_assignment(
                    r,
                    params["form_meta"].cleaned_data['title'],
                    params["form_meta"].cleaned_data['comment'],
                    params["form_assignment"].variables
                )
                utils.set_procmailrc(request.user, procmailrc)
                return redirect("procmail:edit", id=id)
    else:
        if r.is_recipe():
            params["form_meta"] = forms.MetaForm(statement=r, prefix="meta")
            params["form_header"] = forms.HeaderForm(header=r.header, prefix="header")
            params["form_action"] = forms.ActionForm(action=r.action, prefix="action")
            params["form_condition"] = forms.ConditionFormSet(
                conditions=r.conditions,
                prefix="condition"
            )
        elif r.is_assignment():
            params["form_meta"] = forms.MetaForm(statement=r, prefix="meta")
            params["form_assignment"] = forms.AssignmentFormSet(assignment=r, prefix="assignment")
    return render(request, "procmail/edit.html", utils.context(request, params))


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


@login_required
def move(request, old_id, new_id, curr_id):
    try:
        procmailrc = utils.get_procmailrc(request.user)
    except ParseException:
        return HttpResponseServerError(
            "Syntax error in procmailrc",
            content_type="text/plain; charset=utf-8"
        )
    try:
        current_item = procmailrc[curr_id]
        old_parent = procmailrc[utils.get_parent_id(old_id)]
        new_parent = procmailrc[utils.get_parent_id(new_id)]
        r = old_parent.pop(utils.get_current_index(old_id))
        new_parent.insert(utils.get_current_index(new_id), r)
        utils.set_procmailrc(request.user, procmailrc)
        return HttpResponse(current_item.id, content_type="text/plain; charset=utf-8")
    except KeyError:
        raise Http404()


@csrf_exempt
def reverse_view(request):
    view_name = request.POST.get('view_name', "")
    args = json.loads(request.POST.get('args', "[]"))
    kwargs = json.loads(request.POST.get("kwargs", "{}"))
    return HttpResponse(reverse(view_name, args=args, kwargs=kwargs))
