from django import forms
from django.forms.formsets import BaseFormSet


def set_extra(self, **kwargs):
    self.extra = dict(kwargs)
    return self


def prepare_extra(form, field):
    try:
        field.extra = dict(field.extra)
        try:
            field_name, selected = field.extra['show_if_selected']
            field.extra['show_if_selected'] = (form[field_name], selected)
        except KeyError:
            pass
        try:
            field_name = field.extra['show_if_checked']
            field.extra['show_if_checked'] = form[field_name]
        except KeyError:
            pass
    except AttributeError:
        pass


class Extra(forms.Form):
    def prepare_extra(self):
        for field_name, field in self.fields.items():
            prepare_extra(self, field)

    def __init__(self, *args, **kwargs):
        super(Extra, self).__init__(*args, **kwargs)
        self.prepare_extra()


class ExtraSet(BaseFormSet):
    def prepare_extra(self):
        for form in self.forms:
            for field_name, field in form.fields.items():
                prepare_extra(form, field)

    def __init__(self, *args, **kwargs):
        super(ExtraSet, self).__init__(*args, **kwargs)
        self.prepare_extra()


class HidableFieldsFormSet(object):
    def show_init(self):
        for form in self:
            for field_name, field in form.fields.items():
                field.show = self._show(field_name)
        return ""

    def _show(self, field_name):
        try:
            if field_name in self._show_dict:
                return self._show_dict[field_name]
        except AttributeError:
            self._show_dict = {}

        i = 0
        for form in self:
            try:
                not_value = form.fields[field_name].extra['show_if_value_not']
                if self.data and form.add_prefix(field_name) in self.data:
                    ini = form.fields[field_name].to_python(self.data[form.add_prefix(field_name)])
                elif form.data and form.add_prefix(field_name) in form.data:
                    ini = form.fields[field_name].to_python(form.data[form.add_prefix(field_name)])
                elif self.initial and len(self.initial) > i:
                    ini = self.initial[i].get(field_name, form.fields[field_name].initial)
                else:
                    ini = form.fields[field_name].initial
                if not_value == ini and not form.errors.get(field_name):
                    self._show_dict[field_name] = False
                else:
                    self._show_dict[field_name] = True
                    break
            except KeyError:
                self._show_dict[field_name] = True
                break
            i += 1
        return self._show_dict[field_name]


class HidableFieldsForm(object):
    def show_init(self):
        for field_name, field in self.fields.items():
            try:
                not_value = field.extra['show_if_value_not']
                if self.data and self.add_prefix(field_name) in self.data:
                    value = field.to_python(self.data[self.add_prefix(field_name)])
                elif self.initial:
                    value = self.initial.get(field_name, field.initial)
                else:
                    value = field.initial
                if not_value == value and not self.errors.get(field_name):
                    field.show = False
                else:
                    field.show = True
            except KeyError:
                field.show = True
        return ""
