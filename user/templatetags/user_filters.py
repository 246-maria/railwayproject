from django import template

register = template.Library()

@register.filter
def split_string(value, key):
    return value.split(key)
