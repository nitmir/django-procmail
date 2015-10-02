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
import re
import json

import utils
import exceptions


def simple_recipe(r):
    if r.meta_custom:
        try:
            custom = json.loads(r.meta_custom)
            if not isinstance(custom, dict):
                custom = {}
        except ValueError:
            custom = {}
    else:
        custom = {}
    kind = None
    actions = []
    conditions = []

    if not r.action.is_nested():
        if not r.action.is_save() and not r.action.is_forward():
            # not simple
            raise exceptions.NonSimple()
        if len(r.conditions) <= 1:
            if r.conditions and not utils.is_simple_condition(r.conditions[0]):
                # not simple
                raise exceptions.NonSimple()
            kind = custom.get('kind', "and")
            conditions.append((r.header.flag, r.conditions))
        else:
            kind = "or"
            try:
                conditions.append((r.header.flag, utils.unoring(r.conditions)))
            except exceptions.NonOred:
                if not all(utils.is_simple_condition(c) for c in r.conditions):
                    # not simple
                    raise exceptions.NonSimple()
                kind = "and"
                conditions.append((r.header.flag, r.conditions))
        actions.append((r.header.flag, r.action))
    else:
        if all(utils.is_simple_statement(stmt) for stmt in r):
            if len(r.conditions) <= 1:
                if r.conditions and not utils.is_simple_condition(r.conditions[0]):
                    # not simple
                    raise exceptions.NonSimple()
                kind = custom.get('kind', "and")
                conditions.append((r.header.flag, r.conditions))
            else:
                kind = "or"
                try:
                    conditions.append((r.header.flag, utils.unoring(r.conditions)))
                except exceptions.NonOred:
                    if not all(utils.is_simple_condition(c) for c in r.conditions):
                        # not simple
                        raise exceptions.NonSimple()
                    kind = "and"
                    conditions.append((r.header.flag, r.conditions))
            for stmt in r:
                if stmt.is_assignment():
                    actions.append((stmt.header.flag, stmt))
                else:
                    actions.append((stmt.header.flag, stmt.action))
        else:
            if len(r) > 1:
                kind = "or"
                for stmt in r:
                    if stmt.is_recipe() and stmt.action.is_nested():
                        if not all(utils.is_simple_statement(s) for s in stmt):
                            raise exceptions.NonSimple()
                    elif not stmt.is_recipe() or (
                        not stmt.action.is_save()
                        and not stmt.action.is_forward()
                    ):
                        raise exceptions.NonSimple()
                    try:
                        conditions.append((stmt.header.flag, utils.unoring(stmt.conditions)))
                    except exceptions.NonOred:
                        raise exceptions.NonSimple()
                if not all(s.action == r[0].action for s in r):
                    raise exceptions.NonSimple()
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
                    if not all(utils.is_simple_condition(c) for c in rr.conditions):
                        raise exceptions.NonSimple()
                    conditions.append((rr.header.flag, rr.conditions))
                    rr = rr[0]
                conditions.append((rr.header.flag, rr.conditions))
                if not all(utils.is_simple_statement(stmt) for stmt in rr):
                    raise exceptions.NonSimple()
                for stmt in rr:
                    if stmt.is_assignment():
                        actions.append((stmt.header.flag, stmt))
                    else:
                        actions.append((stmt.header.flag, stmt.action))

    meta_initial = meta_form(r)

    cond_kind_initial = {'kind': kind}

    conditions_initial = []
    for flag, conds in conditions:
        for cond in conds:
            conditions_initial.append(simple_condition(flag, cond))

    actions_initial = []
    for flag, action in actions:
        actions_initial.append(simple_action(flag, action))
    return {
        'meta': meta_initial,
        'condition_kind': cond_kind_initial,
        'conditions': conditions_initial,
        'actions': actions_initial
    }, custom


def simple_condition(flag, condition):
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
        for match, exp in [
            ('contain', contain),
            ('equal', equal),
            ('exists', exists),
            ('regex', regex)
        ]:
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
                    if not i > 0 or not param[i-1] == '\\':
                        match = "regex"
                        param = param + '$'
        if negate:
            data['match'] = "not_%s" % match
        else:
            data['match'] = match
        if match != "regex":
            data['param'] = re.sub('\\\(.)', '\\1', param)
        else:
            data['param'] = param

        return data


def simple_action(flag, action):
    data = {}
    if action.is_statement() and action.is_assignment():
        if len(action.variables) != 1:
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


def conditions_form(conditions):
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


def assignment_form(assignment):
    initials = []
    for (variable_name, value, quote) in assignment.variables:
        initials.append({
            'variable_name': variable_name,
            'value': value,
            'shell': (quote == '`'),
        })
    return initials


def meta_form(obj):
    return {
        'title': obj.meta_title or obj.gen_title(),
        'comment': obj.meta_comment,
    }


def header_form(recipe):
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


def action_form(recipe):
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
